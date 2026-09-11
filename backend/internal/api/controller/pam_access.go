package controller

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cast"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	"github.com/veops/oneterm/internal/service"
	"github.com/veops/oneterm/pkg/db"
)

var pamPolicies = service.NewPAMPolicyService()
var pamRequests = service.NewPAMRequestService()

func (c *Controller) RetryPAMRequestSync(ctx *gin.Context) {
	var input struct {
		Revision uint64 `json:"revision"`
	}
	body, err := pamBody(ctx)
	if err != nil || json.Unmarshal(body, &input) != nil || input.Revision == 0 {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	if err := pamRequests.RetrySync(ctx, ctx.Param("id"), input.Revision); err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(nil))
}

func (c *Controller) GetPAMITSMTemplates(ctx *gin.Context) {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil {
		abortPAM(ctx, service.ErrPAMDenied)
		return
	}
	result, err := service.ListPAMITSMTemplates(ctx.Request.Context(), operator.Uid, ctx.Query("search"))
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(result))
}

func (c *Controller) GetPAMITSMTemplate(ctx *gin.Context) {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil {
		abortPAM(ctx, service.ErrPAMDenied)
		return
	}
	result, err := service.GetPAMITSMTemplate(ctx.Request.Context(), cast.ToInt(ctx.Param("id")), operator.Uid, ctx.Query("initiate") == "true")
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(result))
}

func pamTarget(ctx *gin.Context) (model.PAMCredentialTarget, bool) {
	target := model.PAMCredentialTarget{Kind: ctx.Param("kind"), ID: cast.ToInt(ctx.Param("id"))}
	if _, err := repository.CredentialOwnerModel(target.Kind); err != nil || target.ID <= 0 {
		abortPAM(ctx, service.ErrPAMInput)
		return target, false
	}
	return target, true
}

func (c *Controller) GetPAMPolicy(ctx *gin.Context) {
	target, valid := pamTarget(ctx)
	if !valid {
		return
	}
	owner, err := repository.LoadCredentialOwner(ctx.Request.Context(), db.GetDB(), target)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	if !hasPerm(ctx, owner, target.Kind, acl.READ) && !hasPerm(ctx, owner, target.Kind, acl.RequestAccess) &&
		!hasPerm(ctx, owner, target.Kind, acl.ManagePolicy) {
		abortPAM(ctx, service.ErrPAMDenied)
		return
	}
	policy, err := pamPolicies.Get(ctx.Request.Context(), target)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	// Retrieval is configured globally; do not present retired per-account flags to the editor.
	filtered := model.Slice[string]{}
	for _, action := range policy.RequireApprovalActions {
		if action != acl.Retrieve {
			filtered = append(filtered, action)
		}
	}
	policy.RequireApprovalActions = filtered
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(policy))
}

func (c *Controller) SavePAMPolicy(ctx *gin.Context) {
	target, valid := pamTarget(ctx)
	if !valid {
		return
	}
	body, err := pamBody(ctx)
	var input service.PAMPolicyInput
	if err != nil || json.Unmarshal(body, &input) != nil {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	policy, err := pamPolicies.Save(ctx, target, input)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(policy))
}

func (c *Controller) CreatePAMRequest(ctx *gin.Context) {
	body, err := pamBody(ctx)
	var input service.PAMRequestInput
	if err != nil || json.Unmarshal(body, &input) != nil {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	request, err := pamRequests.Create(ctx, input)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(request))
}

func (c *Controller) GetPAMRequests(ctx *gin.Context) {
	pamPagination(ctx)
	query, err := pamRequests.Query(ctx, ctx.Query("view"))
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	query = db.FilterEqual(ctx, query, "state", "target_kind", "target_id", "action")
	doGet[*model.PAMAccessRequest](ctx, false, query, "")
}

func (c *Controller) GetPAMRequestTargets(ctx *gin.Context) {
	pamPagination(ctx)
	query, err := pamRequests.Targets(ctx)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	doGet[*service.PAMRequestTarget](ctx, false, query, "")
}

type pamRequestBinding struct {
	ID         uint64              `json:"id"`
	AssetID    int                 `json:"asset_id"`
	AccountID  int                 `json:"account_id"`
	AssetName  string              `json:"asset_name"`
	TargetHost string              `json:"target_host"`
	Protocols  model.Slice[string] `json:"protocols"`
}

func (c *Controller) GetPAMRequestBindings(ctx *gin.Context) {
	account, err := pamAccounts.Get(ctx.Request.Context(), cast.ToInt(ctx.Param("id")))
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	policy, err := pamPolicies.Get(ctx.Request.Context(), model.PAMCredentialTarget{Kind: model.PAMOwnerAccount, ID: account.Id})
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	if !account.Enabled || !policy.AllowRequests || !hasPerm(ctx, account, model.PAMOwnerAccount, acl.RequestAccess) {
		abortPAM(ctx, service.ErrPAMDenied)
		return
	}
	pamPagination(ctx)
	query := db.GetDB().WithContext(ctx.Request.Context()).Model(&model.PAMAssetAccountBinding{}).
		Select("pam_asset_account_binding.id, pam_asset_account_binding.asset_id, pam_asset_account_binding.account_id, pam_asset_account_binding.target_host, pam_asset_account_binding.protocols, asset.name AS asset_name").
		Joins("JOIN asset ON asset.id = pam_asset_account_binding.asset_id AND asset.deleted_at = 0").
		Where("account_id = ? AND pam_asset_account_binding.enabled = ?", account.Id, true)
	if search := ctx.Query("search"); search != "" {
		query = query.Where("asset.name LIKE ? OR pam_asset_account_binding.target_host LIKE ?", "%"+search+"%", "%"+search+"%")
	}
	doGet[*pamRequestBinding](ctx, false, query, "")
}

func (c *Controller) GetPAMRequest(ctx *gin.Context) {
	operator, _ := acl.GetSessionFromCtx(ctx)
	detail, err := pamRequests.Detail(ctx.Request.Context(), operator, ctx.Param("id"))
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(detail))
}

func (c *Controller) CancelPAMRequest(ctx *gin.Context) {
	body, err := pamBody(ctx)
	var input struct {
		Revision uint64 `json:"revision"`
		Reason   string `json:"reason"`
	}
	if err != nil || json.Unmarshal(body, &input) != nil {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	request, err := pamRequests.Cancel(ctx, ctx.Param("id"), input.Revision, input.Reason)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(request))
}
