package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	"github.com/veops/oneterm/pkg/db"
)

func (s *PAMRequestService) Query(ctx *gin.Context, view string) (*gorm.DB, error) {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil || operator.Uid <= 0 {
		return nil, ErrPAMDenied
	}
	query := s.repo.Requests(ctx.Request.Context())
	if view == "" || view == "mine" {
		return query.Where("requester_uid = ?", operator.Uid).Order("created_at DESC"), nil
	}
	if view != "managed" {
		return nil, ErrPAMInput
	}
	if acl.IsAdmin(operator) {
		return query.Order("created_at DESC"), nil
	}
	action := acl.ManagePolicy
	conditions := db.GetDB().Where("1 = 0")
	for _, kind := range []string{model.PAMOwnerAccount, model.PAMOwnerGateway} {
		resources, err := acl.GetRoleResources(ctx.Request.Context(), operator.GetRid(), kind)
		if err != nil {
			return nil, ErrPAMUnavailable
		}
		ids := []int{}
		for _, resource := range resources {
			for _, permission := range resource.Permissions {
				if permission == action {
					ids = append(ids, resource.ResourceId)
					break
				}
			}
		}
		owner, _ := repository.CredentialOwnerModel(kind)
		targets := db.GetDB().Model(owner).Select("id").Where("resource_id IN ?", ids)
		conditions = conditions.Or("target_kind = ? AND target_id IN (?)", kind, targets)
	}
	query = query.Where(conditions)
	return query.Order("created_at DESC"), nil
}

type PAMRequestTarget struct {
	ID                   int    `json:"id"`
	Name                 string `json:"name"`
	Username             string `json:"username"`
	MaxDurationMinutes   int    `json:"max_duration_minutes"`
	ApprovalProvider     string `json:"approval_provider"`
	ITSMTemplateID       int    `json:"itsm_template_id"`
	ITSMTemplateRevision string `json:"itsm_template_revision"`
}

func (s *PAMRequestService) Targets(ctx *gin.Context) (*gorm.DB, error) {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil || operator.Uid <= 0 {
		return nil, ErrPAMDenied
	}
	query := db.GetDB().WithContext(ctx.Request.Context()).Model(&model.Account{Managed: true}).
		Select("account.id, account.name, account.account AS username, policy.max_duration_minutes, "+
			"policy.approval_provider, policy.itsm_template_id, policy.itsm_template_revision").
		Joins("JOIN pam_policy AS policy ON policy.target_kind = ? AND policy.target_id = account.id", model.PAMOwnerAccount).
		Where("account.managed = ? AND account.enabled = ? AND policy.allow_requests = ?", true, true, true)
	if !acl.IsAdmin(operator) {
		resources, err := acl.GetRoleResources(ctx.Request.Context(), operator.GetRid(), model.PAMOwnerAccount)
		if err != nil {
			return nil, ErrPAMUnavailable
		}
		ids := []int{}
		for _, resource := range resources {
			for _, permission := range resource.Permissions {
				if permission == acl.RequestAccess {
					ids = append(ids, resource.ResourceId)
					break
				}
			}
		}
		query = query.Where("account.resource_id IN ?", ids)
	}
	if search := ctx.Query("search"); search != "" {
		query = query.Where("account.name LIKE ? OR account.account LIKE ?", "%"+search+"%", "%"+search+"%")
	}
	return query, nil
}

type PAMRequestTimelineEntry struct {
	ID        uint64                 `json:"id"`
	RequestID string                 `json:"request_id"`
	ActorUID  int                    `json:"actor_uid"`
	Action    string                 `json:"action"`
	Revision  uint64                 `json:"revision"`
	State     string                 `json:"state"`
	Detail    model.Map[string, any] `json:"detail"`
	CreatedAt time.Time              `json:"created_at"`
}

type PAMRequestDetail struct {
	SyncState    string                    `json:"sync_state,omitempty"`
	CanRetrySync bool                      `json:"can_retry_sync"`
	Request      *model.PAMAccessRequest   `json:"request"`
	Events       []PAMRequestTimelineEntry `json:"events"`
	Grant        *model.PAMTemporaryAccess `json:"grant,omitempty"`
	CanCancel    bool                      `json:"can_cancel"`
	CanUse       bool                      `json:"can_use"`
	Protocols    model.Slice[string]       `json:"protocols"`
}

func (s *PAMRequestService) Detail(ctx context.Context, operator *acl.Session, id string) (*PAMRequestDetail, error) {
	if operator == nil || operator.Uid <= 0 {
		return nil, ErrPAMDenied
	}
	request, err := s.repo.Request(ctx, id)
	if err != nil {
		return nil, err
	}
	owner, ownerErr := repository.LoadCredentialOwner(ctx, db.GetDB(), model.PAMCredentialTarget{Kind: request.TargetKind, ID: request.TargetID})
	manager := acl.IsAdmin(operator)
	if ownerErr == nil && !manager && request.RequesterUID != operator.Uid {
		manager, err = pamResourcePermission(ctx, operator, owner, acl.ManagePolicy, true)
		if err != nil {
			return nil, ErrPAMUnavailable
		}
	} else if ownerErr != nil && !errors.Is(ownerErr, gorm.ErrRecordNotFound) {
		return nil, ErrPAMUnavailable
	}
	if request.RequesterUID != operator.Uid && !manager {
		return nil, ErrPAMDenied
	}
	detail := &PAMRequestDetail{Request: request, SyncState: request.SyncState,
		CanCancel:    (manager || request.RequesterUID == operator.Uid) && (request.State == model.PAMRequestPending || request.State == model.PAMRequestApproved),
		CanRetrySync: request.SyncState == "failed" && (manager || request.RequesterUID == operator.Uid),
		Grant:        request.TemporaryAccess(), Events: []PAMRequestTimelineEntry{}}
	var rows []model.PAMAccessAudit
	if err := db.GetDB().WithContext(ctx).Where("access_request_id = ?", id).Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, row := range rows {
		var entry PAMRequestTimelineEntry
		encoded, err := json.Marshal(row.Detail)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(encoded, &entry); err != nil {
			return nil, err
		}
		entry.ID, entry.RequestID, entry.ActorUID, entry.Action, entry.CreatedAt = row.Id, id, row.ACLUID, row.Action, row.CreatedAt
		detail.Events = append(detail.Events, entry)
	}
	if request.RequesterUID == operator.Uid && ownerErr == nil && request.HasActiveAccess(time.Now()) {
		var policy *model.PAMPolicy
		if request.Action == acl.Retrieve {
			rights, permissionErr := loadPasswordViewRights(ctx, operator, owner)
			if permissionErr != nil {
				return nil, ErrPAMUnavailable
			}
			if !rights.Admin && !rights.Direct && !rights.Request {
				return detail, nil
			}
			policy, err = repository.PasswordViewPolicy(db.GetDB().WithContext(ctx))
		} else {
			policy, err = s.repo.Policy(ctx, model.PAMCredentialTarget{Kind: request.TargetKind, ID: request.TargetID})
		}
		if err != nil {
			return nil, err
		}
		detail.CanUse = requestScopeCurrent(ctx, db.GetDB(), request, owner, policy)
		if detail.CanUse && request.Action == "connect" {
			binding, err := requestBinding(ctx, db.GetDB(), PAMRequestInput{Target: model.PAMCredentialTarget{Kind: request.TargetKind, ID: request.TargetID},
				Action: "connect", AssetID: request.AssetID, AccountID: request.AccountID})
			if err != nil {
				return nil, err
			}
			detail.Protocols = binding.Protocols
		}
	}
	return detail, nil
}
