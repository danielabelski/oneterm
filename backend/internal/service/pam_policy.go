package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	"github.com/veops/oneterm/pkg/db"
)

var (
	ErrPAMApprovalRequired    = errors.New("an approved request is required")
	ErrPAMRequestState        = errors.New("the request state no longer permits this operation")
	ErrPAMScopeChanged        = errors.New("the requested scope or policy changed")
	ErrPAMProviderUnavailable = errors.New("the selected approval provider is unavailable")
)

type PAMPolicyInput struct {
	Revision               uint64                `json:"revision"`
	AllowRequests          bool                  `json:"allow_requests"`
	ApprovalProvider       string                `json:"approval_provider"`
	RequiredApprovals      int                   `json:"required_approvals"`
	MaxDurationMinutes     int                   `json:"max_duration_minutes"`
	RequestExpiryMinutes   int                   `json:"request_expiry_minutes"`
	RequireApprovalActions model.Slice[string]   `json:"require_approval_actions"`
	SourceCIDRs            model.Slice[string]   `json:"source_cidrs"`
	AllowApplications      bool                  `json:"allow_applications"`
	ConnectionPermissions  model.AuthPermissions `json:"connection_permissions"`
	MaxSessions            int                   `json:"max_sessions"`
	MaxSessionMinutes      int                   `json:"max_session_minutes"`
	ITSMTemplateID         int                   `json:"itsm_template_id"`
	ITSMTemplateRevision   string                `json:"itsm_template_revision"`
}

type PAMPolicyService struct {
	repo *repository.PAMAccessRepository
}

func NewPAMPolicyService() *PAMPolicyService {
	return &PAMPolicyService{repo: repository.NewPAMAccessRepository()}
}

func normalizePAMRanges(values []string) (model.Slice[string], error) {
	if len(values) > 100 {
		return nil, ErrPAMInput
	}
	seen := make(map[string]bool)
	result := model.Slice[string]{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil || address.Zone() != "" {
				return nil, ErrPAMInput
			}
			address = address.Unmap()
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		value = prefix.Masked().String()
		if !seen[value] {
			result = append(result, value)
			seen[value] = true
		}
	}
	sort.Strings(result)
	return result, nil
}

func normalizePAMPolicy(input *PAMPolicyInput) error {
	if input.RequiredApprovals < 1 || input.RequiredApprovals > 2 || input.MaxDurationMinutes < 1 || input.MaxDurationMinutes > 10080 ||
		input.RequestExpiryMinutes < 1 || input.RequestExpiryMinutes > 43200 || input.MaxSessions < 0 || input.MaxSessions > 1000 ||
		input.MaxSessionMinutes < 0 || input.MaxSessionMinutes > 10080 {
		return ErrPAMInput
	}
	if input.ApprovalProvider != model.PAMApprovalITSM {
		return ErrPAMInput
	}
	if (input.AllowRequests || len(input.RequireApprovalActions) > 0) && (input.ITSMTemplateID <= 0 || input.ITSMTemplateRevision == "") {
		return ErrPAMInput
	}
	allowed := map[string]bool{"connect": true}
	seen := make(map[string]bool)
	actions := model.Slice[string]{}
	for _, action := range input.RequireApprovalActions {
		if !allowed[action] {
			return ErrPAMInput
		}
		if !seen[action] {
			actions = append(actions, action)
			seen[action] = true
		}
	}
	sort.Strings(actions)
	input.RequireApprovalActions = actions
	ranges, err := normalizePAMRanges(input.SourceCIDRs)
	if err != nil {
		return err
	}
	input.SourceCIDRs = ranges
	input.ConnectionPermissions.Connect = true
	input.ConnectionPermissions.Share = false
	return nil
}

func pamResourcePermission(ctx context.Context, operator *acl.Session, owner model.CredentialOwner, action string, allowAdmin bool) (bool, error) {
	if operator == nil || operator.Uid <= 0 {
		return false, nil
	}
	if allowAdmin && acl.IsAdmin(operator) {
		return true, nil
	}
	return acl.HasPermission(ctx, operator.GetRid(), owner.CredentialOwnerKind(), owner.GetResourceId(), action)
}

func (s *PAMPolicyService) Get(ctx context.Context, target model.PAMCredentialTarget) (*model.PAMPolicy, error) {
	return s.repo.Policy(ctx, target)
}

func (s *PAMPolicyService) Save(ctx *gin.Context, target model.PAMCredentialTarget, input PAMPolicyInput) (*model.PAMPolicy, error) {
	if target.Kind != model.PAMOwnerAccount {
		return nil, ErrPAMProviderUnavailable
	}
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil {
		return nil, ErrPAMDenied
	}
	owner, err := repository.LoadCredentialOwner(ctx.Request.Context(), db.GetDB(), target)
	if err != nil {
		return nil, err
	}
	account, managed := owner.(*model.Account)
	if !managed || !account.Managed {
		return nil, ErrPAMDenied
	}
	for _, permission := range []string{acl.ManagePolicy, acl.GRANT} {
		allowed, err := pamResourcePermission(ctx.Request.Context(), operator, owner, permission, true)
		if err != nil || !allowed {
			return nil, ErrPAMDenied
		}
	}
	if !acl.VerifyMFAToken(ctx.Request.Context(), operator, ctx.GetHeader("X-MFA-Token"), acl.PAMMFAPolicy) {
		return nil, ErrPAMMFARequired
	}
	if err := normalizePAMPolicy(&input); err != nil {
		return nil, err
	}
	if input.AllowRequests || len(input.RequireApprovalActions) > 0 {
		template, err := describePAMITSMTemplate(ctx.Request.Context(), input.ITSMTemplateID, operator.Uid, false)
		if err != nil {
			return nil, err
		}
		if template.TemplateRevision != input.ITSMTemplateRevision {
			return nil, ErrPAMScopeChanged
		}
	}
	if owner.CredentialReference() == "" && len(input.RequireApprovalActions) > 0 {
		return nil, ErrPAMScopeChanged
	}
	var saved *model.PAMPolicy
	err = s.repo.WithPolicy(ctx.Request.Context(), target, func(tx *gorm.DB, owner model.CredentialOwner, current *model.PAMPolicy) error {
		account, managed := owner.(*model.Account)
		if !managed || !account.Managed {
			return ErrPAMScopeChanged
		}
		if current.Revision != input.Revision {
			return ErrPAMRevision
		}
		saved = &model.PAMPolicy{Id: current.Id, TargetKind: target.Kind, TargetID: target.ID, Revision: current.Revision + 1,
			AllowRequests: input.AllowRequests, ApprovalProvider: input.ApprovalProvider, RequiredApprovals: input.RequiredApprovals,
			MaxDurationMinutes: input.MaxDurationMinutes, RequestExpiryMinutes: input.RequestExpiryMinutes,
			RequireApprovalActions: input.RequireApprovalActions, SourceCIDRs: input.SourceCIDRs, AllowApplications: input.AllowApplications,
			ConnectionPermissions: input.ConnectionPermissions, MaxSessions: input.MaxSessions, MaxSessionMinutes: input.MaxSessionMinutes,
			ITSMTemplateID: input.ITSMTemplateID, ITSMTemplateRevision: input.ITSMTemplateRevision, CreatorID: current.CreatorID,
			UpdaterID: operator.Uid, CreatedAt: current.CreatedAt}
		if current.Id == 0 {
			saved.CreatorID = operator.Uid
		}
		if err := tx.Select("*").Save(saved).Error; err != nil {
			return err
		}
		now := time.Now()
		if current.Id != 0 {
			if err := tx.Model(&model.PAMAccessRequest{}).Where("policy_id = ? AND state IN ?", current.Id, []string{model.PAMRequestPending, model.PAMRequestApproved}).
				Updates(map[string]any{"state": model.PAMRequestInvalidated, "revision": gorm.Expr("revision + 1"),
					"grant_revoked_at": now, "grant_revoker_uid": operator.Uid, "grant_revoke_reason": "policy_changed",
					"sync_state": "pending", "sync_next_at": now, "sync_lease_owner": "", "sync_lease_until": nil}).Error; err != nil {
				return err
			}

		}
		before, _ := json.Marshal(current)
		after, _ := json.Marshal(saved)
		oldData, newData := model.Map[string, any]{}, model.Map[string, any]{}
		json.Unmarshal(before, &oldData)
		json.Unmarshal(after, &newData)
		if err := tx.Create(&model.History{Type: "pam_policy", TargetId: saved.Id, ActionType: model.ACTION_UPDATE,
			Old: oldData, New: newData, CreatorId: operator.Uid, RemoteIp: ctx.ClientIP(), CreatedAt: now}).Error; err != nil {
			return err
		}
		return nil
	})
	return saved, err
}

func requiresPAMApproval(policy *model.PAMPolicy, action string) bool {
	for _, required := range policy.RequireApprovalActions {
		if required == action {
			return true
		}
	}
	return false
}
