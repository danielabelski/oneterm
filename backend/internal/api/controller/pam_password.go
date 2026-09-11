package controller

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cast"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/service"
	"github.com/veops/oneterm/pkg/config"
	"github.com/veops/oneterm/pkg/db"
)

func passwordAccountAuthority(ctx *gin.Context, permission string, mfa bool) (*model.Account, bool) {
	account, err := pamAccounts.Get(ctx.Request.Context(), cast.ToInt(ctx.Param("id")))
	if err != nil {
		abortPAM(ctx, err)
		return nil, false
	}
	if !account.Managed || !hasPerm(ctx, account, config.RESOURCE_ACCOUNT, permission) {
		abortPAM(ctx, service.ErrPAMDenied)
		return nil, false
	}
	if mfa {
		operator, err := acl.GetSessionFromCtx(ctx)
		scope := acl.PAMMFARotate
		if permission == acl.ManagePolicy {
			scope = acl.PAMMFAPolicy
		}
		if err != nil || !acl.VerifyMFAToken(ctx.Request.Context(), operator, ctx.GetHeader("X-MFA-Token"), scope) {
			abortPAM(ctx, service.ErrPAMMFARequired)
			return nil, false
		}
	}
	ctx.Header("Cache-Control", "no-store")
	return account, true
}

func (c *Controller) SavePAMPasswordConfig(ctx *gin.Context) {
	account, allowed := passwordAccountAuthority(ctx, acl.ManagePolicy, true)
	if !allowed {
		return
	}
	body, err := pamBody(ctx)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	input, err := service.ParsePAMPasswordConfig(body)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	binding, err := service.SavePAMPasswordConfig(ctx, account.Id, cast.ToUint64(ctx.Param("binding_id")), input)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(binding))
}

func (c *Controller) GetPAMPasswordExecutors(ctx *gin.Context) {
	account, allowed := passwordAccountAuthority(ctx, acl.ManagePolicy, false)
	if !allowed {
		return
	}
	var binding model.PAMAssetAccountBinding
	if err := db.GetDB().WithContext(ctx.Request.Context()).Where("id = ? AND account_id = ?",
		cast.ToUint64(ctx.Query("binding_id")), account.Id).First(&binding).Error; err != nil {
		abortPAM(ctx, err)
		return
	}
	query := pamAccounts.Query(ctx).Where("account.managed = ? AND account.platform = ? AND account.enabled = ?", true, account.Platform, true).
		Where("EXISTS (SELECT 1 FROM pam_asset_account_binding b WHERE b.account_id = account.id AND b.asset_id = ? AND b.enabled = ?)", binding.AssetID, true)
	pamPagination(ctx)
	doGet[*model.Account](ctx, true, query, config.RESOURCE_ACCOUNT)
}

func (c *Controller) VerifyPAMPassword(ctx *gin.Context) {
	account, allowed := passwordAccountAuthority(ctx, acl.VerifySecret, false)
	if !allowed {
		return
	}
	body, err := pamBody(ctx)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	input, err := service.ParsePAMPasswordInput(body)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	result, err := service.VerifyPAMPassword(ctx, account.Id, input)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(result))
}

func (c *Controller) StartPAMPasswordChange(ctx *gin.Context) {
	body, err := pamBody(ctx)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	input, err := service.ParsePAMPasswordInput(body)
	if err != nil || (input.Action != acl.RotateSecret && input.Action != acl.RecoverSecret) {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	account, allowed := passwordAccountAuthority(ctx, input.Action, true)
	if !allowed {
		return
	}
	requestCtx, cancel := context.WithTimeout(ctx.Request.Context(), 85*time.Second)
	defer cancel()
	ctx.Request = ctx.Request.WithContext(requestCtx)
	execution, err := service.StartPAMPasswordChange(ctx, account.Id, input)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(execution))
}

type pamExecutionSummary struct {
	model.PAMExecution
	CanResume    bool `json:"can_resume" gorm:"-"`
	CanReconcile bool `json:"can_reconcile" gorm:"-"`
}

func (c *Controller) GetPAMPasswordExecutions(ctx *gin.Context) {
	account, allowed := passwordAccountAuthority(ctx, acl.READ, false)
	if !allowed {
		return
	}
	rotate := hasPerm(ctx, account, config.RESOURCE_ACCOUNT, acl.RotateSecret)
	recover := hasPerm(ctx, account, config.RESOURCE_ACCOUNT, acl.RecoverSecret)
	pamPagination(ctx)
	query := db.GetDB().WithContext(ctx.Request.Context()).Model(&model.PAMExecution{}).Where("account_id = ?", account.Id).Order("created_at DESC, id DESC")
	doGet[*pamExecutionSummary](ctx, false, query, "", func(ctx *gin.Context, rows []*pamExecutionSummary) {
		for _, row := range rows {
			idle := row.LeaseUntil == nil || !row.LeaseUntil.After(time.Now())
			row.CanResume = idle && row.State == model.PAMExecutionPrepared &&
				(row.Action == acl.RotateSecret && rotate || row.Action == acl.RecoverSecret && recover)
			row.CanReconcile = idle && recover && (row.State == model.PAMExecutionChanging || row.State == model.PAMExecutionVerifying ||
				row.State == model.PAMExecutionUnknown || row.State == model.PAMExecutionVerified)
		}
	})
}

func (c *Controller) ContinuePAMPassword(ctx *gin.Context) {
	var execution model.PAMExecution
	accountID := cast.ToInt(ctx.Param("id"))
	if err := db.GetDB().WithContext(ctx.Request.Context()).Where("id = ? AND account_id = ?",
		ctx.Param("execution_id"), accountID).First(&execution).Error; err != nil {
		abortPAM(ctx, err)
		return
	}
	operation := ctx.Param("operation")
	reconcile := operation != "resume"
	if operation != "reconcile" && operation != "resume" && operation != "keep-original" {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	action := acl.RecoverSecret
	if !reconcile {
		action = execution.Action
	}
	if _, allowed := passwordAccountAuthority(ctx, action, true); !allowed {
		return
	}
	if operation == "keep-original" {
		body, err := pamBody(ctx)
		if err != nil {
			abortPAM(ctx, err)
			return
		}
		confirmation, err := service.ParsePAMOriginalConfirmation(body)
		if err != nil || confirmation.Revision != execution.Revision {
			abortPAM(ctx, service.ErrPAMInput)
			return
		}
	}
	requestCtx, cancel := context.WithTimeout(ctx.Request.Context(), 85*time.Second)
	defer cancel()
	ctx.Request = ctx.Request.WithContext(requestCtx)
	result, err := service.ContinuePAMPassword(ctx, accountID, execution.ID, operation)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(result))
}
