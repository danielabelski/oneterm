package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
)

type PAMITSMDecision struct {
	DecidedAt        time.Time `json:"decided_at"`
	EventID          string    `json:"event_id"`
	RequestID        string    `json:"request_id"`
	RequestRevision  uint64    `json:"request_revision"`
	ProviderRevision uint64    `json:"provider_revision"`
	TemplateID       int       `json:"template_id"`
	TemplateRevision string    `json:"template_revision"`
	TicketID         int       `json:"ticket_id"`
	Decision         string    `json:"decision"`
	ApproverUIDs     []int     `json:"approver_uids"`
}

// This is an internal consumer; the caller must authenticate the complete service response first.
func acceptPAMITSMDecision(ctx context.Context, event PAMITSMDecision) error {
	if _, err := uuid.Parse(event.EventID); err != nil {
		return ErrPAMInput
	}
	if event.RequestID == "" || event.RequestRevision == 0 || event.ProviderRevision == 0 || event.TicketID <= 0 || event.TemplateID <= 0 ||
		event.DecidedAt.IsZero() || event.DecidedAt.After(time.Now().Add(time.Minute)) {
		return ErrPAMInput
	}
	switch event.Decision {
	case model.PAMRequestApproved, model.PAMRequestRejected, model.PAMRequestCancelled, model.PAMRequestInvalidated, model.PAMRequestExpired:
	default:
		return ErrPAMInput
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(encoded)
	digest := hex.EncodeToString(hash[:])
	repo := repository.NewPAMAccessRepository()
	initial, err := repo.Request(ctx, event.RequestID)
	if err != nil {
		return err
	}
	target := model.PAMCredentialTarget{Kind: initial.TargetKind, ID: initial.TargetID}
	return repo.WithActionPolicy(ctx, target, initial.Action, func(tx *gorm.DB, owner model.CredentialOwner, policy *model.PAMPolicy) error {
		var request model.PAMAccessRequest
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", event.RequestID).First(&request).Error; err != nil {
			return err
		}
		if request.ApprovalProvider != model.PAMApprovalITSM || request.ITSMTemplateID != event.TemplateID ||
			request.ITSMTemplateRevision != event.TemplateRevision || request.ITSMRequestRevision != event.RequestRevision || request.TicketID != event.TicketID {
			return ErrPAMScopeChanged
		}
		if event.ProviderRevision <= request.ProviderRevision {
			if event.ProviderRevision == request.ProviderRevision && request.ProviderEventID == event.EventID &&
				request.ProviderPayloadHash == digest {
				return nil
			}
			return ErrPAMRevision
		}
		if request.ProviderEventID == event.EventID {
			return ErrPAMRevision
		}
		request.ProviderRevision, request.ProviderEventID, request.ProviderPayloadHash = event.ProviderRevision, event.EventID, digest
		receipt := map[string]any{"provider_revision": event.ProviderRevision, "provider_event_id": event.EventID, "provider_payload_hash": digest}
		if request.State != model.PAMRequestPending && request.State != model.PAMRequestApproved {
			return tx.Model(&request).Updates(receipt).Error
		}
		now := time.Now()
		if event.Decision == model.PAMRequestApproved {
			if request.State == model.PAMRequestApproved {
				return tx.Model(&request).Updates(receipt).Error
			}
			actors := uidSet(event.ApproverUIDs, request.RequesterUID)
			if len(actors) != len(event.ApproverUIDs) || len(actors) < request.RequiredApprovals {
				return ErrPAMDenied
			}
			if event.DecidedAt.Before(request.CreatedAt.Add(-time.Minute)) {
				return ErrPAMScopeChanged
			}
			request.ApproverUIDs = append(model.Slice[int]{}, event.ApproverUIDs...)
			grantExpires := event.DecidedAt.Add(time.Duration(request.DurationMinutes) * time.Minute)
			if !event.DecidedAt.Before(request.ExpiresAt) || !now.Before(grantExpires) {
				request.State = model.PAMRequestExpired
			} else if !requestScopeCurrent(ctx, tx, &request, owner, policy) {
				request.State = model.PAMRequestInvalidated
			} else {
				request.State = model.PAMRequestApproved
				if err := repository.ActivatePAMRequestAccess(tx, &request, event.DecidedAt); err != nil {
					return err
				}
			}
		} else {
			request.State = event.Decision
			if err := repository.RevokePAMRequestAccess(tx, &request, 0, "itsm_"+event.Decision); err != nil {
				return err
			}
		}
		request.Revision++
		if err := tx.Save(&request).Error; err != nil {
			return err
		}
		return repository.WritePAMRequestAudit(tx, &request, 0, "itsm_decision", model.Map[string, any]{
			"ticket_id": event.TicketID, "provider_revision": event.ProviderRevision, "decision": event.Decision, "approver_uids": event.ApproverUIDs,
		})
	})
}
