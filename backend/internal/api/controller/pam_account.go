package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cast"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	"github.com/veops/oneterm/internal/service"
	"github.com/veops/oneterm/pkg/config"
	"github.com/veops/oneterm/pkg/db"
)

var pamAccounts = service.NewPAMAccountService()

type pamAdoptionAsset struct {
	ID        int                 `json:"id"`
	Name      string              `json:"name"`
	IP        string              `json:"ip"`
	Protocols model.Slice[string] `json:"protocols"`
}

func (c *Controller) GetPAMAdoptionAssets(ctx *gin.Context) {
	pamPagination(ctx)
	query, err := pamAccounts.AdoptionAssets(ctx)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	doGet[*pamAdoptionAsset](ctx, false, query, "")
}

func (c *Controller) GetPAMAccount(ctx *gin.Context) {
	account, err := pamAccounts.Get(ctx.Request.Context(), cast.ToInt(ctx.Param("id")))
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	if !account.Managed || !hasPerm(ctx, account, config.RESOURCE_ACCOUNT, acl.READ) {
		abortPAM(ctx, service.ErrPAMDenied)
		return
	}
	if err := handlePermissions(ctx, []*model.Account{account}, config.RESOURCE_ACCOUNT); err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(account))
}

func pamSourceAuthority(ctx *gin.Context, assetID, accountID int) (*acl.Session, bool) {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil {
		abortPAM(ctx, service.ErrPAMDenied)
		return nil, false
	}
	base := service.NewBaseService()
	asset, source := &model.Asset{}, &model.Account{}
	if err := base.GetById(ctx.Request.Context(), assetID, asset); err != nil {
		abortPAM(ctx, err)
		return nil, false
	}
	if err := base.GetById(ctx.Request.Context(), accountID, source); err != nil {
		abortPAM(ctx, err)
		return nil, false
	}
	if !hasPerm(ctx, asset, config.RESOURCE_ASSET, acl.GRANT) || !hasPerm(ctx, source, config.RESOURCE_ACCOUNT, acl.GRANT) ||
		!hasPerm(ctx, source, config.RESOURCE_ACCOUNT, acl.ManagePolicy) {
		abortPAM(ctx, service.ErrPAMDenied)
		return nil, false
	}
	if !acl.VerifyMFAToken(ctx.Request.Context(), operator, ctx.GetHeader("X-MFA-Token"), acl.PAMMFAPolicy) {
		abortPAM(ctx, service.ErrPAMMFARequired)
		return nil, false
	}
	return operator, true
}

func (c *Controller) AdoptPAMAccount(ctx *gin.Context) {
	body, err := pamBody(ctx)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	input, err := service.ParsePAMAdoption(body)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	operator, allowed := pamSourceAuthority(ctx, input.AssetID, input.AccountID)
	if !allowed {
		return
	}
	account, err := pamAccounts.Adopt(ctx, input, operator)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(account))
}

func (c *Controller) GetPAMAccountBindings(ctx *gin.Context) {
	account, err := pamAccounts.Get(ctx.Request.Context(), cast.ToInt(ctx.Param("id")))
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	if !account.Managed || !hasPerm(ctx, account, config.RESOURCE_ACCOUNT, acl.READ) {
		abortPAM(ctx, service.ErrPAMDenied)
		return
	}
	pamPagination(ctx)
	query := pamAccounts.Bindings(ctx.Request.Context(), account.Id)
	if search := ctx.Query("search"); search != "" {
		if len(search) > 128 {
			abortPAM(ctx, service.ErrPAMInput)
			return
		}
		assets := db.GetDB().WithContext(ctx.Request.Context()).Model(&model.Asset{}).Select("id").Where("name LIKE ? OR ip LIKE ?", "%"+search+"%", "%"+search+"%")
		query = query.Where("asset_id IN (?)", assets)
	}
	doGet[*model.PAMAssetAccountBinding](ctx, false, query, "", func(ctx *gin.Context, rows []*model.PAMAssetAccountBinding) {
		assetIDs, accountIDs := []int{}, []int{}
		for _, row := range rows {
			assetIDs = append(assetIDs, row.AssetID)
			accountIDs = append(accountIDs, row.AccountID)
		}
		var assets []model.Asset
		var sources []model.Account
		if err := db.GetDB().WithContext(ctx.Request.Context()).Select("id", "name", "ip", "gateway_id", "protocols").Where("id IN ?", assetIDs).Find(&assets).Error; err != nil {
			abortPAM(ctx, err)
			return
		}
		if err := db.GetDB().WithContext(ctx.Request.Context()).Select("id", "name").Where("id IN ?", accountIDs).Find(&sources).Error; err != nil {
			abortPAM(ctx, err)
			return
		}
		assetMap, accountNames := map[int]model.Asset{}, map[int]string{}
		for _, asset := range assets {
			assetMap[asset.Id] = asset
		}
		for _, source := range sources {
			accountNames[source.Id] = source.Name
		}
		for _, row := range rows {
			asset := assetMap[row.AssetID]
			row.AssetName, row.AccountName, row.CurrentHost = asset.Name, accountNames[row.AccountID], asset.Ip
			row.RouteChanged = !repository.BindingMatchesAsset(row, &asset)
		}
	})
}

func (c *Controller) AttachPAMAccount(ctx *gin.Context) {
	var input service.PAMBindingInput
	if err := ctx.ShouldBindBodyWithJSON(&input); err != nil || input.AssetID <= 0 || input.AccountID <= 0 {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	account, err := pamAccounts.Get(ctx.Request.Context(), cast.ToInt(ctx.Param("id")))
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	if !hasPerm(ctx, account, config.RESOURCE_ACCOUNT, acl.ManagePolicy) || !hasPerm(ctx, account, config.RESOURCE_ACCOUNT, acl.GRANT) {
		abortPAM(ctx, service.ErrPAMDenied)
		return
	}
	operator, allowed := pamSourceAuthority(ctx, input.AssetID, input.AccountID)
	if !allowed {
		return
	}
	binding, err := pamAccounts.Attach(ctx, account.Id, input, operator)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(binding))
}

func managedPAMAuthority(ctx *gin.Context, id int) (*model.Account, *acl.Session, bool) {
	account, err := pamAccounts.Get(ctx.Request.Context(), id)
	if err != nil {
		abortPAM(ctx, err)
		return nil, nil, false
	}
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil || !account.Managed || !hasPerm(ctx, account, config.RESOURCE_ACCOUNT, acl.ManagePolicy) {
		abortPAM(ctx, service.ErrPAMDenied)
		return nil, nil, false
	}
	if !acl.VerifyMFAToken(ctx.Request.Context(), operator, ctx.GetHeader("X-MFA-Token"), acl.PAMMFAPolicy) {
		abortPAM(ctx, service.ErrPAMMFARequired)
		return nil, nil, false
	}
	return account, operator, true
}

func (c *Controller) DisablePAMAccount(ctx *gin.Context) {
	var input struct {
		Revision uint64 `json:"revision"`
	}
	if err := ctx.ShouldBindBodyWithJSON(&input); err != nil {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	account, operator, allowed := managedPAMAuthority(ctx, cast.ToInt(ctx.Param("id")))
	if !allowed {
		return
	}
	updated, err := pamAccounts.Disable(ctx, account.Id, input.Revision, operator)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(updated))
}

func (c *Controller) RemovePAMAccountManagement(ctx *gin.Context) {
	var input struct {
		Revision uint64 `json:"revision"`
	}
	if err := ctx.ShouldBindBodyWithJSON(&input); err != nil {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	account, operator, allowed := managedPAMAuthority(ctx, cast.ToInt(ctx.Param("id")))
	if !allowed {
		return
	}
	if !hasPerm(ctx, account, config.RESOURCE_ACCOUNT, acl.GRANT) {
		abortPAM(ctx, service.ErrPAMDenied)
		return
	}
	if err := pamAccounts.RemoveManagement(ctx, account.Id, input.Revision, operator); err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(map[string]any{"id": account.Id, "managed": false}))
}

func (c *Controller) EnablePAMAccount(ctx *gin.Context) {
	var input struct {
		Revision uint64 `json:"revision"`
	}
	if err := ctx.ShouldBindBodyWithJSON(&input); err != nil {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	account, operator, allowed := managedPAMAuthority(ctx, cast.ToInt(ctx.Param("id")))
	if !allowed {
		return
	}
	updated, err := pamAccounts.SetEnabled(ctx, account.Id, input.Revision, true, operator)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(updated))
}

func (c *Controller) ReviewPAMBinding(ctx *gin.Context) {
	var input service.PAMBindingInput
	if err := ctx.ShouldBindBodyWithJSON(&input); err != nil {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	account, _, allowed := managedPAMAuthority(ctx, cast.ToInt(ctx.Param("id")))
	if !allowed {
		return
	}
	operator, allowed := pamSourceAuthority(ctx, input.AssetID, input.AccountID)
	if !allowed {
		return
	}
	updated, err := pamAccounts.ReviewBinding(ctx, account.Id, input, operator)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(updated))
}
