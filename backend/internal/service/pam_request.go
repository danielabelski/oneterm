package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	gsession "github.com/veops/oneterm/internal/session"
	"github.com/veops/oneterm/pkg/db"
)

type PAMRequestInput struct {
	ITSMNodeInfo    model.Map[string, any]    `json:"itsm_node_info,omitempty"`
	IdempotencyKey  string                    `json:"idempotency_key"`
	Target          model.PAMCredentialTarget `json:"target"`
	Action          string                    `json:"action"`
	AssetID         int                       `json:"asset_id"`
	AccountID       int                       `json:"account_id"`
	DurationMinutes int                       `json:"duration_minutes"`
	Reason          string                    `json:"reason"`
}

type PAMRequestService struct {
	repo *repository.PAMAccessRepository
}

func NewPAMRequestService() *PAMRequestService {
	return &PAMRequestService{repo: repository.NewPAMAccessRepository()}
}

func requestIntent(input *PAMRequestInput) (string, error) {
	input.Reason = strings.TrimSpace(input.Reason)
	if input.IdempotencyKey == "" || len(input.IdempotencyKey) > 64 || input.Target.ID <= 0 || input.DurationMinutes < 1 ||
		input.Reason == "" || utf8.RuneCountInString(input.Reason) > 2048 {
		return "", ErrPAMInput
	}
	if input.Action != "connect" && input.Action != acl.Retrieve {
		return "", ErrPAMInput
	}
	if input.Action != "connect" && (input.AssetID != 0 || input.AccountID != 0) {
		return "", ErrPAMInput
	}
	data, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func uidSet(uids []int, excluded int) map[int]bool {
	result := make(map[int]bool)
	for _, uid := range uids {
		if uid > 0 && uid != excluded {
			result[uid] = true
		}
	}
	return result
}

func requestBinding(ctx context.Context, tx *gorm.DB, input PAMRequestInput) (*model.PAMAssetAccountBinding, error) {
	if input.Action != "connect" {
		return nil, nil
	}
	if input.Target.Kind != model.PAMOwnerAccount || input.AssetID <= 0 || input.AccountID <= 0 || input.Target.ID != input.AccountID {
		return nil, ErrPAMInput
	}
	var binding model.PAMAssetAccountBinding
	if err := tx.WithContext(ctx).Where("asset_id = ? AND account_id = ?", input.AssetID, input.AccountID).
		First(&binding).Error; err != nil {
		return nil, ErrPAMDenied
	}
	var asset model.Asset
	if err := tx.WithContext(ctx).First(&asset, binding.AssetID).Error; err != nil {
		return nil, ErrPAMDenied
	}
	if !binding.Enabled || !repository.BindingMatchesAsset(&binding, &asset) {
		return nil, ErrPAMScopeChanged
	}
	return &binding, nil
}

func (s *PAMRequestService) Create(ctx *gin.Context, input PAMRequestInput) (*model.PAMAccessRequest, error) {
	if input.Action == acl.Retrieve {
		return s.CreatePasswordViewRequest(ctx, input)
	}
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil || operator.Uid <= 0 {
		return nil, ErrPAMDenied
	}
	intent, err := requestIntent(&input)
	if err != nil {
		return nil, err
	}
	if previous, err := s.repo.RequestByKey(ctx.Request.Context(), operator.Uid, input.IdempotencyKey); err == nil {
		if !hmac.Equal([]byte(previous.IntentHash), []byte(intent)) {
			return nil, ErrPAMRevision
		}
		return previous, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrPAMUnavailable
	}
	owner, err := repository.LoadCredentialOwner(ctx.Request.Context(), db.GetDB(), input.Target)
	if err != nil {
		return nil, ErrPAMDenied
	}
	policy, err := s.repo.Policy(ctx.Request.Context(), input.Target)
	if err != nil {
		return nil, err
	}
	requestPermission, err := pamResourcePermission(ctx.Request.Context(), operator, owner, acl.RequestAccess, true)
	account, managed := owner.(*model.Account)
	if !managed || !account.Managed {
		return nil, ErrPAMDenied
	}
	if err != nil {
		return nil, ErrPAMUnavailable
	}
	standing := false
	if !(policy.AllowRequests && requestPermission) && input.Action == "connect" && requiresPAMApproval(policy, "connect") {
		if DefaultAuthService == nil {
			return nil, ErrPAMUnavailable
		}
		result, err := DefaultAuthService.HasStandingAuthorizationV2(ctx,
			&gsession.Session{Session: &model.Session{AssetId: input.AssetID, AccountId: input.AccountID}}, model.ActionConnect)
		if err != nil {
			return nil, ErrPAMUnavailable
		}
		standing = result.IsAllowed(model.ActionConnect)
	}
	if !(policy.AllowRequests && requestPermission) && !(standing && requiresPAMApproval(policy, input.Action)) {
		return nil, ErrPAMDenied
	}
	if policy.ApprovalProvider != model.PAMApprovalITSM {
		return nil, ErrPAMProviderUnavailable
	}
	template, err := describePAMITSMTemplate(ctx.Request.Context(), policy.ITSMTemplateID, operator.Uid, true)
	if err != nil {
		return nil, err
	}
	if template.TemplateRevision != policy.ITSMTemplateRevision || input.ITSMNodeInfo == nil {
		return nil, ErrPAMScopeChanged
	}
	var created *model.PAMAccessRequest
	err = s.repo.WithPolicy(ctx.Request.Context(), input.Target, func(tx *gorm.DB, owner model.CredentialOwner, current *model.PAMPolicy) error {
		if current.Id == 0 || current.Revision != policy.Revision {
			return ErrPAMScopeChanged
		}
		available, err := repository.CredentialOwnerAvailable(ctx.Request.Context(), tx, owner)
		if err != nil {
			return err
		}
		if !available || !sourceAllowed(ctx.ClientIP(), current.SourceCIDRs) {
			return ErrPAMDenied
		}
		if input.DurationMinutes > current.MaxDurationMinutes {
			return ErrPAMInput
		}
		var previous model.PAMAccessRequest
		err = tx.Where("requester_uid = ? AND idempotency_key = ?", operator.Uid, input.IdempotencyKey).First(&previous).Error
		if err == nil {
			if previous.IntentHash != intent {
				return ErrPAMRevision
			}
			created = &previous
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		binding, err := requestBinding(ctx.Request.Context(), tx, input)
		if err != nil {
			return err
		}
		created = &model.PAMAccessRequest{ID: uuid.NewString(), RequesterUID: operator.Uid, IdempotencyKey: input.IdempotencyKey,
			IntentHash: intent, TargetKind: input.Target.Kind, TargetID: input.Target.ID, Action: input.Action,
			TargetName: owner.GetName(), TargetUsername: credentialResponse(owner).Account,
			AssetID: input.AssetID, AccountID: input.AccountID, PolicyID: current.Id, PolicyRevision: current.Revision,
			DurationMinutes: input.DurationMinutes, Reason: input.Reason, State: model.PAMRequestPending, Revision: 1,
			ApprovalProvider: current.ApprovalProvider, RequiredApprovals: current.RequiredApprovals,
			ITSMTemplateID: current.ITSMTemplateID, ITSMTemplateRevision: current.ITSMTemplateRevision,
			ITSMNodeInfo: input.ITSMNodeInfo, ITSMRequestRevision: 1,
			ConnectionPermissions: current.ConnectionPermissions, ExpiresAt: time.Now().Add(time.Duration(current.RequestExpiryMinutes) * time.Minute)}
		if binding != nil {
			created.BindingID, created.BindingRevision = binding.ID, binding.Revision
			var asset model.Asset
			if err := tx.Select("name").First(&asset, binding.AssetID).Error; err != nil {
				return err
			}
			created.AssetName, created.TargetHost, created.BindingProtocols = asset.Name, binding.TargetHost, binding.Protocols
		}
		repository.SchedulePAMRequestSync(created)
		if err := tx.Create(created).Error; err != nil {
			return err
		}
		if err := repository.WritePAMRequestAudit(tx, created, operator.Uid, "submitted", nil); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		translated := err
		if translator, ok := db.GetDB().Dialector.(gorm.ErrorTranslator); ok {
			translated = translator.Translate(err)
		}
		if errors.Is(translated, gorm.ErrDuplicatedKey) {
			previous, lookupErr := s.repo.RequestByKey(ctx.Request.Context(), operator.Uid, input.IdempotencyKey)
			if lookupErr == nil {
				if previous.IntentHash != intent {
					return nil, ErrPAMRevision
				}
				return previous, nil
			}
		}
		return nil, err
	}
	return created, nil
}

func requestScopeCurrent(ctx context.Context, tx *gorm.DB, request *model.PAMAccessRequest, owner model.CredentialOwner, policy *model.PAMPolicy) bool {
	if request.PolicyID != policy.Id || request.PolicyRevision != policy.Revision {
		return false
	}
	if request.TargetKind != owner.CredentialOwnerKind() || request.TargetID != owner.GetId() {
		return false
	}
	if request.Action == acl.Retrieve {
		return policy.TargetKind == model.PAMPasswordViewPolicy && requiresPAMApproval(policy, acl.Retrieve) &&
			passwordViewOwnerAvailable(owner) && request.CredentialVersionID == passwordViewVersion(owner) &&
			request.TargetUsername == credentialResponse(owner).Account
	}
	available, err := repository.CredentialOwnerAvailable(ctx, tx, owner)
	if err != nil || !available {
		return false
	}
	if request.Action == "connect" {
		binding, err := requestBinding(ctx, tx, PAMRequestInput{Target: model.PAMCredentialTarget{Kind: request.TargetKind, ID: request.TargetID},
			Action: request.Action, AssetID: request.AssetID, AccountID: request.AccountID})
		return err == nil && binding.ID == request.BindingID && binding.Revision == request.BindingRevision
	}
	return true
}

func (s *PAMRequestService) Cancel(ctx *gin.Context, id string, revision uint64, reason string) (*model.PAMAccessRequest, error) {
	if revision == 0 || utf8.RuneCountInString(reason) > 1024 {
		return nil, ErrPAMInput
	}
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil {
		return nil, ErrPAMDenied
	}
	initial, err := s.repo.Request(ctx.Request.Context(), id)
	if err != nil {
		return nil, err
	}
	if operator.Uid != initial.RequesterUID {
		owner, err := repository.LoadCredentialOwner(ctx.Request.Context(), db.GetDB(), model.PAMCredentialTarget{Kind: initial.TargetKind, ID: initial.TargetID})
		if err != nil {
			return nil, ErrPAMDenied
		}
		allowed, err := pamResourcePermission(ctx.Request.Context(), operator, owner, acl.ManagePolicy, true)
		if err != nil || !allowed {
			return nil, ErrPAMDenied
		}
		if !acl.VerifyMFAToken(ctx.Request.Context(), operator, ctx.GetHeader("X-MFA-Token"), acl.PAMMFAPolicy) {
			return nil, ErrPAMMFARequired
		}
	}
	var result *model.PAMAccessRequest
	err = s.repo.WithRequest(ctx.Request.Context(), id, func(tx *gorm.DB, request *model.PAMAccessRequest) error {
		result = request
		if request.State == model.PAMRequestCancelled {
			return nil
		}
		if request.Revision != revision || (request.State != model.PAMRequestPending && request.State != model.PAMRequestApproved) {
			return ErrPAMRequestState
		}
		request.State, request.Revision = model.PAMRequestCancelled, request.Revision+1
		repository.SchedulePAMRequestSync(request)
		if err := tx.Save(request).Error; err != nil {
			return err
		}
		if err := repository.RevokePAMRequestAccess(tx, request, operator.Uid, reason); err != nil {
			return err
		}
		return repository.WritePAMRequestAudit(tx, request, operator.Uid, "cancelled", model.Map[string, any]{"reason": reason})
	})
	return result, err
}
