package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/pkg/db"
)

type PAMAccessRepository struct{ database *gorm.DB }

func NewPAMAccessRepository() *PAMAccessRepository { return &PAMAccessRepository{database: db.GetDB()} }

func DefaultPAMPolicy(target model.PAMCredentialTarget) *model.PAMPolicy {
	return &model.PAMPolicy{TargetKind: target.Kind, TargetID: target.ID, AllowApplications: true,
		ApprovalProvider: model.PAMApprovalITSM, RequiredApprovals: 1, MaxDurationMinutes: 60, RequestExpiryMinutes: 1440,
		RequireApprovalActions: model.Slice[string]{}, SourceCIDRs: model.Slice[string]{},
		ConnectionPermissions: model.AuthPermissions{Connect: true}}
}

func (r *PAMAccessRepository) Policy(ctx context.Context, target model.PAMCredentialTarget) (*model.PAMPolicy, error) {
	return PAMPolicyInTransaction(r.database.WithContext(ctx), target)
}

func PAMPolicyInTransaction(tx *gorm.DB, target model.PAMCredentialTarget) (*model.PAMPolicy, error) {
	var policy model.PAMPolicy
	err := tx.Where("target_kind = ? AND target_id = ?", target.Kind, target.ID).First(&policy).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return DefaultPAMPolicy(target), nil
	}
	return &policy, err
}

// Lock order is target, policy, request for all PAM decision transactions.
func (r *PAMAccessRepository) WithPolicy(ctx context.Context, target model.PAMCredentialTarget, fn func(*gorm.DB, model.CredentialOwner, *model.PAMPolicy) error) error {
	return r.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return WithPAMPolicy(tx, target, "UPDATE", fn)
	})
}

func WithPAMPolicy(tx *gorm.DB, target model.PAMCredentialTarget, strength string, fn func(*gorm.DB, model.CredentialOwner, *model.PAMPolicy) error) error {
	return WithPAMActionPolicy(tx, target, "", strength, fn)
}

func (r *PAMAccessRepository) WithActionPolicy(ctx context.Context, target model.PAMCredentialTarget, action string, fn func(*gorm.DB, model.CredentialOwner, *model.PAMPolicy) error) error {
	return r.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return WithPAMActionPolicy(tx, target, action, "UPDATE", fn)
	})
}

func PasswordViewPolicy(tx *gorm.DB) (*model.PAMPolicy, error) {
	var policy model.PAMPolicy
	err := tx.Where("target_kind = ? AND target_id = ?", model.PAMPasswordViewPolicy, 0).First(&policy).Error
	return &policy, err
}

// Credential reads and connection policies share locking, not policy scope.
func WithPAMActionPolicy(tx *gorm.DB, target model.PAMCredentialTarget, action, strength string, fn func(*gorm.DB, model.CredentialOwner, *model.PAMPolicy) error) error {
	owner, err := CredentialOwnerModel(target.Kind)
	if err != nil {
		return err
	}
	if err := tx.Clauses(clause.Locking{Strength: strength}).First(owner, target.ID).Error; err != nil {
		return err
	}
	var policy *model.PAMPolicy
	if action == "retrieve" {
		policy, err = PasswordViewPolicy(tx.Clauses(clause.Locking{Strength: strength}))
	} else {
		policy, err = PAMPolicyInTransaction(tx.Clauses(clause.Locking{Strength: strength}), target)
	}
	if err != nil {
		return err
	}
	return fn(tx, owner, policy)
}

func (r *PAMAccessRepository) Request(ctx context.Context, id string) (*model.PAMAccessRequest, error) {
	var request model.PAMAccessRequest
	err := r.database.WithContext(ctx).Where("id = ?", id).First(&request).Error
	return &request, err
}

func (r *PAMAccessRepository) RequestByKey(ctx context.Context, uid int, key string) (*model.PAMAccessRequest, error) {
	var request model.PAMAccessRequest
	err := r.database.WithContext(ctx).Where("requester_uid = ? AND idempotency_key = ?", uid, key).First(&request).Error
	return &request, err
}

func (r *PAMAccessRepository) Requests(ctx context.Context) *gorm.DB {
	return r.database.WithContext(ctx).Model(&model.PAMAccessRequest{})
}

func (r *PAMAccessRepository) WithRequest(ctx context.Context, id string, fn func(*gorm.DB, *model.PAMAccessRequest) error) error {
	return r.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var request model.PAMAccessRequest
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", id).First(&request).Error; err != nil {
			return err
		}
		return fn(tx, &request)
	})
}

func WritePAMRequestAudit(tx *gorm.DB, request *model.PAMAccessRequest, uid int, action string, detail model.Map[string, any]) error {
	if detail == nil {
		detail = model.Map[string, any]{}
	}
	actorType := "user"
	if uid == 0 {
		actorType = "system"
	}
	now := time.Now()
	return tx.Create(&model.PAMAccessAudit{RequestID: uuid.NewString(), AccessRequestID: request.ID,
		ActorType: actorType, ActorID: uid, ACLUID: uid, TargetKind: request.TargetKind, TargetID: request.TargetID,
		Action: action, Outcome: "succeeded", FinishedAt: &now,
		Detail: model.Map[string, any]{"revision": request.Revision, "state": request.State, "detail": detail}}).Error
}

func SchedulePAMRequestSync(request *model.PAMAccessRequest) {
	if request.ApprovalProvider != model.PAMApprovalITSM {
		return
	}
	now := time.Now()
	request.SyncState, request.SyncNextAt = "pending", &now
	request.SyncAttempts, request.SyncErrorCode = 0, ""
	request.SyncLeaseOwner, request.SyncLeaseUntil = "", nil
}

// Change the same object as the caller so a later Save cannot overwrite revocation.
func RevokePAMRequestAccess(tx *gorm.DB, request *model.PAMAccessRequest, uid int, reason string) error {
	if request.GrantRevokedAt == nil {
		now := time.Now()
		request.GrantRevokedAt, request.GrantRevokerUID, request.GrantRevokeReason = &now, uid, reason
	}
	return tx.Model(request).Updates(map[string]any{"grant_revoked_at": request.GrantRevokedAt,
		"grant_revoker_uid": request.GrantRevokerUID, "grant_revoke_reason": request.GrantRevokeReason}).Error
}

func ActivatePAMRequestAccess(tx *gorm.DB, request *model.PAMAccessRequest, from time.Time) error {
	if request.GrantedAt != nil || request.GrantRevokedAt != nil {
		return ErrCredentialState
	}
	until := from.Add(time.Duration(request.DurationMinutes) * time.Minute)
	request.GrantedAt, request.GrantedUntil = &from, &until
	return tx.Model(request).Updates(map[string]any{"granted_at": from, "granted_until": until}).Error
}
