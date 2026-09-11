package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	"github.com/veops/oneterm/pkg/db"
)

type PasswordViewSettings struct {
	Revision             uint64 `json:"revision"`
	RequireApproval      bool   `json:"require_approval"`
	TemplateID           int    `json:"template_id"`
	TemplateName         string `json:"template_name"`
	TemplateRevision     string `json:"template_revision"`
	ApprovalValidMinutes int    `json:"approval_valid_minutes"`
}

type PasswordViewStatus struct {
	State            string                  `json:"state"`
	RequireApproval  bool                    `json:"require_approval"`
	TemplateID       int                     `json:"template_id"`
	TemplateName     string                  `json:"template_name"`
	TemplateRevision string                  `json:"template_revision"`
	ValidMinutes     int                     `json:"valid_minutes"`
	CanView          bool                    `json:"can_view"`
	CanRequest       bool                    `json:"can_request"`
	CanCancel        bool                    `json:"can_cancel"`
	Request          *model.PAMAccessRequest `json:"request,omitempty"`
}

// Initialize once at startup, never once per account. Old approval requirements fail closed.
func EnsurePasswordViewPolicy(ctx context.Context) error {
	_, err := repository.PasswordViewPolicy(db.GetDB().WithContext(ctx))
	if err == nil {
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	var old []model.PAMPolicy
	if err := db.GetDB().WithContext(ctx).Where("target_kind <> ?", model.PAMPasswordViewPolicy).Find(&old).Error; err != nil {
		return err
	}
	policy := repository.DefaultPAMPolicy(model.PAMCredentialTarget{Kind: model.PAMPasswordViewPolicy})
	policy.Revision, policy.MaxDurationMinutes, policy.AllowApplications = 1, 5, false
	policy.ConnectionPermissions = model.AuthPermissions{}
	for _, previous := range old {
		if requiresPAMApproval(&previous, acl.Retrieve) {
			policy.RequireApprovalActions = model.Slice[string]{acl.Retrieve}
			policy.AllowRequests = true
			break
		}
	}
	return db.GetDB().WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(policy).Error
}

func passwordViewSettings(policy *model.PAMPolicy) *PasswordViewSettings {
	return &PasswordViewSettings{Revision: policy.Revision, RequireApproval: requiresPAMApproval(policy, acl.Retrieve),
		TemplateID: policy.ITSMTemplateID, TemplateName: policy.ITSMTemplateName, TemplateRevision: policy.ITSMTemplateRevision,
		ApprovalValidMinutes: policy.MaxDurationMinutes}
}

func GetPasswordViewSettings(ctx context.Context) (*PasswordViewSettings, error) {
	policy, err := repository.PasswordViewPolicy(db.GetDB().WithContext(ctx))
	if err != nil {
		return nil, err
	}
	return passwordViewSettings(policy), nil
}

func CanConfigurePasswordView(ctx context.Context, operator *acl.Session) (bool, error) {
	if operator == nil || operator.Uid <= 0 {
		return false, nil
	}
	if acl.IsAdmin(operator) {
		return true, nil
	}
	resources, err := acl.GetRoleResources(ctx, operator.GetRid(), "OperationPermission")
	if err != nil {
		return false, err
	}
	for _, resource := range resources {
		if resource.Name == "System_Config" {
			for _, permission := range resource.Permissions {
				if permission == "password_view" {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func SavePasswordViewSettings(ctx *gin.Context, input PasswordViewSettings) (*PasswordViewSettings, error) {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil {
		return nil, ErrPAMDenied
	}
	allowed, err := CanConfigurePasswordView(ctx.Request.Context(), operator)
	if err != nil {
		return nil, ErrPAMUnavailable
	}
	if !allowed {
		return nil, ErrPAMDenied
	}
	if !acl.VerifyMFAToken(ctx.Request.Context(), operator, ctx.GetHeader("X-MFA-Token"), acl.PAMMFAPolicy) {
		return nil, ErrPAMMFARequired
	}
	if input.ApprovalValidMinutes < 1 || input.ApprovalValidMinutes > 60 {
		return nil, ErrPAMInput
	}
	var template *PAMITSMTemplate
	if input.RequireApproval {
		if input.TemplateID <= 0 {
			return nil, ErrPAMInput
		}
		template, err = describePAMITSMTemplate(ctx.Request.Context(), input.TemplateID, operator.Uid, false)
		if err != nil {
			return nil, err
		}
		if input.TemplateRevision != "" && input.TemplateRevision != template.TemplateRevision {
			return nil, ErrPAMScopeChanged
		}
	}
	var result *PasswordViewSettings
	err = db.GetDB().WithContext(ctx.Request.Context()).Transaction(func(tx *gorm.DB) error {
		policy, err := repository.PasswordViewPolicy(tx.Clauses(clause.Locking{Strength: "UPDATE"}))
		if err != nil {
			return err
		}
		if policy.Revision != input.Revision {
			return ErrPAMRevision
		}
		before, _ := json.Marshal(passwordViewSettings(policy))
		policy.Revision++
		policy.MaxDurationMinutes, policy.RequiredApprovals = input.ApprovalValidMinutes, 1
		policy.RequireApprovalActions = model.Slice[string]{}
		policy.AllowRequests = input.RequireApproval
		policy.ITSMTemplateID, policy.ITSMTemplateName, policy.ITSMTemplateRevision = 0, "", ""
		policy.UpdaterID = operator.Uid
		if template != nil {
			policy.RequireApprovalActions = model.Slice[string]{acl.Retrieve}
			policy.ITSMTemplateID, policy.ITSMTemplateName, policy.ITSMTemplateRevision = template.TemplateID, template.TemplateName, template.TemplateRevision
		}
		if err := tx.Select("*").Save(policy).Error; err != nil {
			return err
		}
		now := time.Now()
		if err := tx.Model(&model.PAMAccessRequest{}).Where("action = ? AND state IN ?", acl.Retrieve,
			[]string{model.PAMRequestPending, model.PAMRequestApproved}).Updates(map[string]any{
			"state": model.PAMRequestInvalidated, "revision": gorm.Expr("revision + 1"), "grant_revoked_at": now,
			"grant_revoker_uid": operator.Uid, "grant_revoke_reason": "password_view_settings_changed",
			"sync_state": "pending", "sync_next_at": now, "sync_lease_owner": "", "sync_lease_until": nil,
		}).Error; err != nil {
			return err
		}
		result = passwordViewSettings(policy)
		after, _ := json.Marshal(result)
		oldData, newData := model.Map[string, any]{}, model.Map[string, any]{}
		json.Unmarshal(before, &oldData)
		json.Unmarshal(after, &newData)
		return tx.Create(&model.History{Type: "pam_policy", TargetId: policy.Id, ActionType: model.ACTION_UPDATE,
			Old: oldData, New: newData, CreatorId: operator.Uid, RemoteIp: ctx.ClientIP()}).Error
	})
	return result, err
}

// Legacy credentials stay in place; hash stored ciphertext only to detect replacement.
func passwordViewVersion(owner model.CredentialOwner) string {
	if version := owner.CredentialReference(); version != "" {
		return version
	}
	password, key, phrase := owner.CredentialValues()
	encoded, _ := json.Marshal([]any{owner.CredentialAuthType(), password, key, phrase})
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:])
}

func passwordViewOwnerAvailable(owner model.CredentialOwner) bool {
	account, ok := owner.(*model.Account)
	return !ok || !account.Managed || account.Enabled
}

func authorizePasswordView(tx *gorm.DB, owner model.CredentialOwner, policy *model.PAMPolicy,
	operator *acl.Session, rights passwordViewRights) (*model.PAMTemporaryAccess, error) {
	if operator == nil || operator.Uid <= 0 || !rights.eligible(policy) || !passwordViewOwnerAvailable(owner) {
		return nil, ErrPAMDenied
	}
	if !rights.needsApproval(policy) {
		return nil, nil
	}
	grant, err := findPAMGrant(tx, pamGrantScope{UID: operator.Uid, Action: acl.Retrieve, Owner: owner, Policy: policy})
	if err != nil {
		return nil, ErrPAMUnavailable
	}
	if grant == nil {
		return nil, ErrPAMApprovalRequired
	}
	return grant, nil
}

func newPasswordViewStatus(policy *model.PAMPolicy, rights passwordViewRights) *PasswordViewStatus {
	status := &PasswordViewStatus{State: "not_required", CanView: rights.Admin || rights.Direct}
	if status.CanView {
		return status
	}
	status.State = "approval_disabled"
	if rights.needsApproval(policy) {
		status.RequireApproval, status.State = true, "configuration_required"
		status.TemplateID, status.TemplateName, status.TemplateRevision = policy.ITSMTemplateID, policy.ITSMTemplateName, policy.ITSMTemplateRevision
		status.ValidMinutes = policy.MaxDurationMinutes
		status.CanRequest = policy.ITSMTemplateID > 0
		if status.CanRequest {
			status.State = "required"
		}
	}
	return status
}

func (s *PAMRequestService) PasswordViewStatus(ctx *gin.Context, target model.PAMCredentialTarget) (*PasswordViewStatus, error) {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil || operator.Uid <= 0 {
		return nil, ErrPAMDenied
	}
	owner, err := repository.LoadCredentialOwner(ctx.Request.Context(), db.GetDB(), target)
	if err != nil {
		return nil, ErrPAMDenied
	}
	rights, err := loadPasswordViewRights(ctx.Request.Context(), operator, owner)
	if err != nil {
		return nil, ErrPAMUnavailable
	}
	policy, err := repository.PasswordViewPolicy(db.GetDB().WithContext(ctx.Request.Context()))
	if err != nil {
		return nil, ErrPAMUnavailable
	}
	if (!rights.Admin && !rights.Direct && !rights.Request) || !passwordViewOwnerAvailable(owner) {
		return nil, ErrPAMDenied
	}
	status := newPasswordViewStatus(policy, rights)
	if !status.CanRequest {
		return status, nil
	}
	var latest model.PAMAccessRequest
	err = s.repo.Requests(ctx.Request.Context()).Where("requester_uid = ? AND target_kind = ? AND target_id = ? AND action = ?",
		operator.Uid, target.Kind, target.ID, acl.Retrieve).Order("created_at DESC, id DESC").First(&latest).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return status, nil
	}
	if err != nil {
		return nil, ErrPAMUnavailable
	}
	applyPasswordViewRequest(ctx.Request.Context(), status, &latest, owner, policy)
	return status, nil
}

func applyPasswordViewRequest(ctx context.Context, status *PasswordViewStatus, latest *model.PAMAccessRequest, owner model.CredentialOwner, policy *model.PAMPolicy) {
	status.Request, status.State = latest, latest.State
	if latest.State == model.PAMRequestPending || latest.State == model.PAMRequestApproved {
		if !requestScopeCurrent(ctx, db.GetDB(), latest, owner, policy) {
			status.State = model.PAMRequestInvalidated
		} else if (latest.State == model.PAMRequestPending && !time.Now().Before(latest.ExpiresAt)) ||
			(latest.State == model.PAMRequestApproved && !latest.HasActiveAccess(time.Now())) {
			status.State = model.PAMRequestExpired
		} else {
			status.CanView = latest.HasActiveAccess(time.Now())
			status.CanRequest, status.CanCancel = false, true
		}
	}
}

func (s *PAMRequestService) CreatePasswordViewRequest(ctx *gin.Context, input PAMRequestInput) (*model.PAMAccessRequest, error) {
	if input.Action != acl.Retrieve {
		return nil, ErrPAMInput
	}
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil || operator.Uid <= 0 {
		return nil, ErrPAMDenied
	}
	owner, err := repository.LoadCredentialOwner(ctx.Request.Context(), db.GetDB(), input.Target)
	if err != nil {
		return nil, ErrPAMDenied
	}
	rights, err := loadPasswordViewRights(ctx.Request.Context(), operator, owner)
	if err != nil {
		return nil, ErrPAMUnavailable
	}
	policy, err := repository.PasswordViewPolicy(db.GetDB().WithContext(ctx.Request.Context()))
	if err != nil {
		return nil, ErrPAMUnavailable
	}
	if !rights.canRequest() {
		return nil, ErrPAMDenied
	}
	if !rights.needsApproval(policy) {
		return nil, ErrPAMRequestState
	}
	if policy.ITSMTemplateID <= 0 {
		return nil, ErrPAMProviderUnavailable
	}
	if input.DurationMinutes != 0 && input.DurationMinutes != policy.MaxDurationMinutes {
		return nil, ErrPAMInput
	}
	input.DurationMinutes = policy.MaxDurationMinutes
	intent, err := requestIntent(&input)
	if err != nil {
		return nil, err
	}
	template, err := describePAMITSMTemplate(ctx.Request.Context(), policy.ITSMTemplateID, operator.Uid, true)
	if err != nil {
		return nil, err
	}
	if input.ITSMNodeInfo == nil || template.TemplateRevision != policy.ITSMTemplateRevision {
		return nil, ErrPAMScopeChanged
	}
	var result *model.PAMAccessRequest
	err = s.repo.WithActionPolicy(ctx.Request.Context(), input.Target, acl.Retrieve, func(tx *gorm.DB, current model.CredentialOwner, cfg *model.PAMPolicy) error {
		if cfg.Revision != policy.Revision || current.GetResourceId() != owner.GetResourceId() || !passwordViewOwnerAvailable(current) {
			return ErrPAMScopeChanged
		}
		var previous model.PAMAccessRequest
		err := tx.Where("requester_uid = ? AND idempotency_key = ?", operator.Uid, input.IdempotencyKey).First(&previous).Error
		if err == nil {
			if previous.IntentHash != intent {
				return ErrPAMRevision
			}
			if !requestScopeCurrent(ctx.Request.Context(), tx, &previous, current, cfg) {
				return ErrPAMScopeChanged
			}
			result = &previous
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		var active []model.PAMAccessRequest
		if err := tx.Where("requester_uid = ? AND target_kind = ? AND target_id = ? AND action = ? AND state IN ?",
			operator.Uid, input.Target.Kind, input.Target.ID, acl.Retrieve, []string{model.PAMRequestPending, model.PAMRequestApproved}).
			Order("created_at DESC, id DESC").Find(&active).Error; err != nil {
			return err
		}
		for _, item := range active {
			if requestScopeCurrent(ctx.Request.Context(), tx, &item, current, cfg) &&
				((item.State == model.PAMRequestPending && time.Now().Before(item.ExpiresAt)) || item.HasActiveAccess(time.Now())) {
				result = &item
				return nil
			}
			item.State, item.Revision = model.PAMRequestInvalidated, item.Revision+1
			repository.SchedulePAMRequestSync(&item)
			if err := repository.RevokePAMRequestAccess(tx, &item, operator.Uid, "password_view_scope_changed"); err != nil {
				return err
			}
			if err := tx.Save(&item).Error; err != nil {
				return err
			}
		}
		result = &model.PAMAccessRequest{ID: uuid.NewString(), RequesterUID: operator.Uid, IdempotencyKey: input.IdempotencyKey,
			IntentHash: intent, TargetKind: input.Target.Kind, TargetID: input.Target.ID, TargetName: current.GetName(),
			TargetUsername: credentialResponse(current).Account, Action: acl.Retrieve, PolicyID: cfg.Id, PolicyRevision: cfg.Revision,
			CredentialVersionID: passwordViewVersion(current), DurationMinutes: cfg.MaxDurationMinutes, Reason: input.Reason,
			State: model.PAMRequestPending, Revision: 1, ApprovalProvider: model.PAMApprovalITSM, RequiredApprovals: 1,
			ITSMTemplateID: cfg.ITSMTemplateID, ITSMTemplateRevision: cfg.ITSMTemplateRevision, ITSMNodeInfo: input.ITSMNodeInfo,
			ITSMRequestRevision: 1, ExpiresAt: time.Now().Add(time.Duration(cfg.RequestExpiryMinutes) * time.Minute)}
		repository.SchedulePAMRequestSync(result)
		if err := tx.Create(result).Error; err != nil {
			return err
		}
		return repository.WritePAMRequestAudit(tx, result, operator.Uid, "submitted", nil)
	})
	return result, err
}
