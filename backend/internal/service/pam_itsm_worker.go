package service

import (
	"context"
	"errors"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	"github.com/veops/oneterm/pkg/db"
	"github.com/veops/oneterm/pkg/logger"
)

func pamITSMCreatePayload(request *model.PAMAccessRequest) map[string]any {
	return map[string]any{
		"request_id": request.ID, "request_revision": request.ITSMRequestRevision, "requester_uid": request.RequesterUID,
		"template_id": request.ITSMTemplateID, "template_revision": request.ITSMTemplateRevision, "node_info": request.ITSMNodeInfo,
		"scope": map[string]any{
			"target_kind": request.TargetKind, "target_id": request.TargetID, "target_name": request.TargetName,
			"target_username": request.TargetUsername, "asset_id": request.AssetID, "account_id": request.AccountID,
			"asset_name": request.AssetName, "target_host": request.TargetHost, "action": request.Action, "reason": request.Reason,
			"duration_minutes": request.DurationMinutes, "policy_id": request.PolicyID, "policy_revision": request.PolicyRevision,
			"binding_id": request.BindingID, "binding_revision": request.BindingRevision, "credential_version_id": request.CredentialVersionID,
			"connection_permissions": request.ConnectionPermissions, "expires_at": request.ExpiresAt,
		},
	}
}

func bindITSMTicket(ctx context.Context, requestID string, status PAMITSMStatus) error {
	return db.GetDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var request model.PAMAccessRequest
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", requestID).First(&request).Error; err != nil {
			return err
		}
		if status.TicketID <= 0 || status.RequestID != request.ID || status.RequestRevision != request.ITSMRequestRevision ||
			status.TemplateID != request.ITSMTemplateID || status.TemplateRevision != request.ITSMTemplateRevision ||
			(request.TicketID != 0 && request.TicketID != status.TicketID) {
			return ErrPAMScopeChanged
		}
		return tx.Model(&request).Update("ticket_id", status.TicketID).Error
	})
}

func expirePAMITSMRequest(ctx context.Context, request *model.PAMAccessRequest) error {
	return repository.NewPAMAccessRepository().WithRequest(ctx, request.ID, func(tx *gorm.DB, current *model.PAMAccessRequest) error {
		now := time.Now()
		expired := current.State == model.PAMRequestPending && !now.Before(current.ExpiresAt)
		if current.State == model.PAMRequestApproved && current.GrantedUntil != nil {
			expired = !now.Before(*current.GrantedUntil)
		}
		if expired {
			current.State, current.Revision = model.PAMRequestExpired, current.Revision+1
			if err := tx.Save(current).Error; err != nil {
				return err
			}
			if err := repository.RevokePAMRequestAccess(tx, current, 0, "expired"); err != nil {
				return err
			}
			if err := repository.WritePAMRequestAudit(tx, current, 0, "expired", nil); err != nil {
				return err
			}
		}
		*request = *current
		return nil
	})
}

func syncPAMITSMRequest(ctx context.Context, request *model.PAMAccessRequest) (bool, error) {
	if request.ApprovalProvider != model.PAMApprovalITSM {
		return true, ErrPAMInput
	}
	// Before creating a remote ticket, expire locally; for an existing ticket first
	// retrieve a possibly delayed decision made before the pending deadline.
	if request.TicketID == 0 {
		if err := expirePAMITSMRequest(ctx, request); err != nil {
			return false, err
		}
	}
	identity := map[string]any{"request_id": request.ID, "request_revision": request.ITSMRequestRevision}
	terminal := request.State != model.PAMRequestPending && request.State != model.PAMRequestApproved
	var status PAMITSMStatus
	if request.TicketID == 0 {
		if terminal {
			if err := callPAMITSM(ctx, "cancel", identity, &status); err != nil {
				return false, err
			}
			if status.RequestID != request.ID || status.RequestRevision != request.ITSMRequestRevision || status.Decision != "cancelled" {
				return false, ErrPAMScopeChanged
			}
			return true, nil
		}
		if err := callPAMITSM(ctx, "create", pamITSMCreatePayload(request), &status); err != nil {
			return false, err
		}
		if status.TicketID == 0 {
			return false, nil
		}
		if err := bindITSMTicket(ctx, request.ID, status); err != nil {
			return false, err
		}
		request.TicketID = status.TicketID
	} else {
		operation := "status"
		if terminal {
			operation = "cancel"
		}
		if err := callPAMITSM(ctx, operation, identity, &status); err != nil {
			return false, err
		}
		if err := bindITSMTicket(ctx, request.ID, status); err != nil {
			return false, err
		}
	}
	if status.Event != nil {
		if err := acceptPAMITSMDecision(ctx, *status.Event); err != nil {
			return false, err
		}
	}
	if err := expirePAMITSMRequest(ctx, request); err != nil {
		return false, err
	}
	// A newly invalidated/expired request must close unfinished remote work before synchronization ends.
	if !terminal && (request.State == model.PAMRequestExpired || request.State == model.PAMRequestInvalidated) {
		if err := callPAMITSM(ctx, "cancel", identity, &status); err != nil {
			return false, err
		}
		if err := bindITSMTicket(ctx, request.ID, status); err != nil {
			return false, err
		}
		return true, nil
	}
	if terminal || status.Decision == model.PAMRequestRejected || status.Decision == model.PAMRequestCancelled ||
		status.Decision == model.PAMRequestInvalidated || status.Decision == model.PAMRequestExpired {
		return true, nil
	}
	if request.GrantedUntil != nil && !time.Now().Before(*request.GrantedUntil) {
		return true, nil
	}
	return false, nil
}

// Synchronization belongs to the request. Claims never overwrite its business state.
func ProcessPAMITSMWork(ctx context.Context, limit int) error {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	for index := 0; index < limit; index++ {
		var claimed model.PAMAccessRequest
		owner := uuid.NewString()
		err := db.GetDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			now := time.Now()
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
				Where("approval_provider = ? AND sync_state IN ? AND sync_next_at <= ? AND (sync_lease_until IS NULL OR sync_lease_until < ?)",
					model.PAMApprovalITSM, []string{"pending", "running"}, now, now).
				Order("sync_next_at, id").First(&claimed).Error; err != nil {
				return err
			}
			until := now.Add(time.Minute)
			return tx.Model(&claimed).Updates(map[string]any{"sync_state": "running", "sync_lease_owner": owner, "sync_lease_until": until}).Error
		})
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		var current model.PAMAccessRequest
		done := false
		err = db.GetDB().WithContext(ctx).Where("id = ?", claimed.ID).First(&current).Error
		if err == nil {
			done, err = syncPAMITSMRequest(ctx, &current)
		}
		updates := map[string]any{"sync_lease_owner": "", "sync_lease_until": nil, "sync_state": "pending"}
		if err != nil {
			attempts := claimed.SyncAttempts + 1
			fields := []zap.Field{zap.String("request_id", claimed.ID), zap.Int("attempt", attempts)}
			var remote *pamITSMRemoteError
			if errors.As(err, &remote) {
				fields = append(fields, zap.Int("http_status", remote.Status), zap.String("code", remote.Code))
			}
			logger.L().Warn("PAM ITSM request synchronization failed", fields...)
			delay := time.Duration(1<<min(attempts, 8)) * time.Second
			updates["sync_attempts"], updates["sync_error_code"], updates["sync_next_at"] = attempts, "itsm_sync_failed", time.Now().Add(delay)
			if attempts >= 8 {
				updates["sync_state"] = "failed"
			}
		} else {
			updates["sync_attempts"], updates["sync_error_code"], updates["sync_next_at"] = 0, "", time.Now().Add(15*time.Second)
			if done {
				updates["sync_state"] = "done"
			}
		}
		if err := db.GetDB().WithContext(ctx).Model(&model.PAMAccessRequest{}).
			Where("id = ? AND sync_lease_owner = ?", claimed.ID, owner).Updates(updates).Error; err != nil {
			return err
		}
	}
	return nil
}

// Retry only delivery/status synchronization; workflow repair stays in the existing ITSM UI.
func (s *PAMRequestService) RetrySync(ctx *gin.Context, id string, revision uint64) error {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil {
		return ErrPAMDenied
	}
	detail, err := s.Detail(ctx.Request.Context(), operator, id)
	if err != nil {
		return err
	}
	if !detail.CanRetrySync {
		return ErrPAMRequestState
	}
	return s.repo.WithRequest(ctx.Request.Context(), id, func(tx *gorm.DB, request *model.PAMAccessRequest) error {
		if revision != request.Revision || request.ApprovalProvider != model.PAMApprovalITSM {
			return ErrPAMRevision
		}
		if request.SyncState != "failed" {
			return ErrPAMRequestState
		}
		repository.SchedulePAMRequestSync(request)
		if err := tx.Model(request).Updates(map[string]any{"sync_state": request.SyncState, "sync_attempts": 0,
			"sync_next_at": request.SyncNextAt, "sync_error_code": "", "sync_lease_owner": "", "sync_lease_until": nil}).Error; err != nil {
			return err
		}
		return repository.WritePAMRequestAudit(tx, request, operator.Uid, "itsm_sync_retry", nil)
	})
}
