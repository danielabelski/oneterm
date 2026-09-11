package controller

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cast"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/service"
	apiErrors "github.com/veops/oneterm/pkg/errors"
)

func (c *Controller) GetPasswordViewSettings(ctx *gin.Context) {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil {
		abortPAM(ctx, service.ErrPAMDenied)
		return
	}
	allowed, err := service.CanConfigurePasswordView(ctx.Request.Context(), operator)
	if err != nil {
		abortPAM(ctx, service.ErrPAMUnavailable)
		return
	}
	if !allowed {
		ctx.AbortWithError(http.StatusForbidden, &apiErrors.ApiError{Code: apiErrors.ErrNoPerm,
			Data: map[string]any{"perm": "System_Config.password_view"}})
		return
	}
	settings, err := service.GetPasswordViewSettings(ctx.Request.Context())
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(settings))
}

func (c *Controller) SavePasswordViewSettings(ctx *gin.Context) {
	var input service.PasswordViewSettings
	body, err := pamBody(ctx)
	if err != nil || json.Unmarshal(body, &input) != nil {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	settings, err := service.SavePasswordViewSettings(ctx, input)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(settings))
}

func (c *Controller) GetPasswordViewStatus(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")
	target, valid := pamTarget(ctx)
	if !valid {
		return
	}
	status, err := pamRequests.PasswordViewStatus(ctx, target)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(status))
}

func (c *Controller) CreatePasswordViewRequest(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")
	target, valid := pamTarget(ctx)
	if !valid {
		return
	}
	var input struct {
		IdempotencyKey string                 `json:"idempotency_key"`
		Reason         string                 `json:"reason"`
		NodeInfo       model.Map[string, any] `json:"node_info"`
	}
	body, err := pamBody(ctx)
	if err != nil || json.Unmarshal(body, &input) != nil {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	request, err := pamRequests.CreatePasswordViewRequest(ctx, service.PAMRequestInput{
		Target: target, Action: acl.Retrieve, Reason: input.Reason, IdempotencyKey: input.IdempotencyKey, ITSMNodeInfo: input.NodeInfo,
	})
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(request))
}

func (c *Controller) ReadPasswordView(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")
	target, valid := pamTarget(ctx)
	if !valid {
		return
	}
	credential, err := service.RetrievePasswordView(ctx, target)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(credential))
}

func (c *Controller) GetPasswordViewAccounts(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")
	page, size := pamPagination(ctx)
	rows, count, err := pamRequests.PasswordViewAccounts(ctx, page, size, cast.ToInt(ctx.Query("account_id")))
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(gin.H{"list": rows, "count": count}))
}

func (c *Controller) GetPasswordViewAudit(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")
	pamPagination(ctx)
	query, err := service.PasswordViewAuditQuery(ctx)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	doGet[*service.PasswordViewAuditEntry](ctx, false, query, "")
}
