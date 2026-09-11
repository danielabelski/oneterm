package service

import (
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	"github.com/veops/oneterm/pkg/db"
)

type PasswordViewAccount struct {
	ID          int                 `json:"id"`
	Name        string              `json:"name"`
	Account     string              `json:"account"`
	AccountType int                 `json:"account_type"`
	View        *PasswordViewStatus `json:"view"`
}

// List metadata only, filtering by account ACL before pagination; no asset or management prerequisite.
func (s *PAMRequestService) PasswordViewAccounts(ctx *gin.Context, page, size, accountID int) ([]PasswordViewAccount, int64, error) {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil || operator.Uid <= 0 {
		return nil, 0, ErrPAMDenied
	}
	if acl.IsAdmin(operator) {
		return []PasswordViewAccount{}, 0, nil
	}
	policy, err := repository.PasswordViewPolicy(db.GetDB().WithContext(ctx.Request.Context()))
	if err != nil {
		return nil, 0, ErrPAMUnavailable
	}
	rightsByResource := map[int]passwordViewRights{}
	query := db.GetDB().WithContext(ctx.Request.Context()).Model(&model.Account{}).
		Where("managed = ? OR enabled = ?", false, true)
	{
		resources, err := acl.GetRoleResources(ctx.Request.Context(), operator.GetRid(), model.PAMOwnerAccount)
		if err != nil {
			return nil, 0, ErrPAMUnavailable
		}
		ids := []int{}
		for _, resource := range resources {
			rights := passwordViewRights{}
			for _, action := range resource.Permissions {
				rights.Direct = rights.Direct || action == acl.Retrieve
				rights.Request = rights.Request || action == PasswordViewRequestPermission
			}
			if rights.canRequest() {
				rightsByResource[resource.ResourceId] = rights
				ids = append(ids, resource.ResourceId)
			}
		}
		if len(ids) == 0 {
			return []PasswordViewAccount{}, 0, nil
		}
		query = query.Where("resource_id IN ?", ids)
	}
	if search := strings.TrimSpace(ctx.Query("search")); search != "" {
		query = query.Where("name LIKE ? OR account LIKE ?", "%"+search+"%", "%"+search+"%")
	}
	if accountID > 0 {
		query = query.Where("id = ?", accountID)
	}
	var count int64
	if err := query.Session(&gorm.Session{}).Count(&count).Error; err != nil {
		return nil, 0, err
	}
	var accounts []model.Account
	if err := query.Offset((page - 1) * size).Limit(size).Order("id DESC").Find(&accounts).Error; err != nil {
		return nil, 0, err
	}
	ids := make([]int, 0, len(accounts))
	for _, account := range accounts {
		ids = append(ids, account.Id)
	}
	requests := map[int]*model.PAMAccessRequest{}
	if len(ids) > 0 && requiresPAMApproval(policy, acl.Retrieve) {
		// One latest request per account on this page, not the complete request history.
		latest := db.GetDB().Table("pam_access_request AS latest").Select("latest.id").
			Where("latest.requester_uid = current.requester_uid AND latest.target_kind = current.target_kind AND latest.target_id = current.target_id AND latest.action = current.action").
			Order("latest.created_at DESC, latest.id DESC").Limit(1)
		var rows []*model.PAMAccessRequest
		if err := db.GetDB().WithContext(ctx.Request.Context()).Table("pam_access_request AS current").Select("current.*").
			Where("current.requester_uid = ? AND current.target_kind = ? AND current.action = ? AND current.target_id IN ?", operator.Uid, model.PAMOwnerAccount, acl.Retrieve, ids).
			Where("current.id = (?)", latest).Find(&rows).Error; err != nil {
			return nil, 0, err
		}
		for _, row := range rows {
			requests[row.TargetID] = row
		}
	}
	result := make([]PasswordViewAccount, 0, len(accounts))
	for _, account := range accounts {
		rights := rightsByResource[account.ResourceId]
		status := newPasswordViewStatus(policy, rights)
		if status.CanRequest {
			if request := requests[account.Id]; request != nil {
				applyPasswordViewRequest(ctx.Request.Context(), status, request, &account, policy)
			}
		}
		result = append(result, PasswordViewAccount{ID: account.Id, Name: account.Name, Account: account.Account,
			AccountType: account.AccountType, View: status})
	}
	return result, count, nil
}
