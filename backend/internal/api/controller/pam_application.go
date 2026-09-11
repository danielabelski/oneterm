package controller

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cast"
	"gorm.io/gorm"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	"github.com/veops/oneterm/internal/service"
	"github.com/veops/oneterm/pkg/config"
	"github.com/veops/oneterm/pkg/db"
	apiErrors "github.com/veops/oneterm/pkg/errors"
)

var pamApplications = service.NewPAMApplicationService()

type pamTargetSummary struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Account string `json:"account"`
}

func abortPAM(ctx *gin.Context, err error) {
	if translator, ok := db.GetDB().Dialector.(gorm.ErrorTranslator); ok {
		err = translator.Translate(err)
	}
	status, code := http.StatusServiceUnavailable, apiErrors.ErrPAMUnavailable
	switch {
	case errors.Is(err, service.ErrPAMCredentialShared):
		status, code = http.StatusConflict, apiErrors.ErrPAMCredentialShared
	case errors.Is(err, repository.ErrPAMBindingChanged):
		status, code = http.StatusConflict, apiErrors.ErrPAMBindingChanged
	case errors.Is(err, repository.ErrPAMBindingUnavailable):
		status, code = http.StatusForbidden, apiErrors.ErrPAMBindingUnavailable
	case errors.Is(err, service.ErrPAMInput), errors.Is(err, service.ErrCredentialInput):
		status, code = http.StatusBadRequest, apiErrors.ErrPAMInput
	case errors.Is(err, service.ErrPAMMFARequired):
		status, code = http.StatusUnauthorized, apiErrors.ErrMFARequired
	case errors.Is(err, acl.ErrPAMKeyEvidence):
		status, code = http.StatusUnauthorized, apiErrors.ErrPAMIdentity
	case errors.Is(err, service.ErrPAMDenied):
		status, code = http.StatusForbidden, apiErrors.ErrPAMDenied
	case errors.Is(err, service.ErrPAMTemplateDenied):
		status, code = http.StatusForbidden, apiErrors.ErrPAMTemplateDenied
	case errors.Is(err, service.ErrPAMReplay):
		status, code = http.StatusUnauthorized, apiErrors.ErrPAMReplay
	case errors.Is(err, service.ErrPAMRevision):
		status, code = http.StatusConflict, apiErrors.ErrPAMRevision
	case errors.Is(err, service.ErrPAMApprovalRequired):
		status, code = http.StatusForbidden, apiErrors.ErrPAMApprovalRequired
	case errors.Is(err, service.ErrPAMRequestState):
		status, code = http.StatusConflict, apiErrors.ErrPAMRequestState
	case errors.Is(err, repository.ErrPAMExecutionState):
		status, code = http.StatusConflict, apiErrors.ErrPAMExecutionState
	case errors.Is(err, service.ErrPAMScopeChanged):
		status, code = http.StatusConflict, apiErrors.ErrPAMScopeChanged
	case errors.Is(err, service.ErrPAMProviderUnavailable):
		status, code = http.StatusConflict, apiErrors.ErrPAMProviderUnavailable
	case errors.Is(err, gorm.ErrDuplicatedKey):
		status, code = http.StatusConflict, apiErrors.ErrPAMConflict
	case errors.Is(err, gorm.ErrRecordNotFound):
		status, code = http.StatusNotFound, apiErrors.ErrPAMDenied
	}
	ctx.AbortWithError(status, &apiErrors.ApiError{Code: code})
}

func pamBody(ctx *gin.Context) ([]byte, error) {
	if cached, present := ctx.Get(gin.BodyBytesKey); present {
		body, ok := cached.([]byte)
		if !ok || len(body) > 65536 {
			return nil, service.ErrPAMInput
		}
		return body, nil
	}
	body, err := io.ReadAll(io.LimitReader(ctx.Request.Body, 65537))
	if err != nil || len(body) > 65536 {
		return nil, service.ErrPAMInput
	}
	return body, nil
}

func pamPagination(ctx *gin.Context) (int, int) {
	query := ctx.Request.URL.Query()
	page, size := cast.ToInt(query.Get("page_index")), cast.ToInt(query.Get("page_size"))
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > 200 {
		size = 200
	}
	query.Set("page_index", strconv.Itoa(page))
	query.Set("page_size", strconv.Itoa(size))
	ctx.Request.URL.RawQuery = query.Encode()
	return page, size
}

func (c *Controller) GetPAMApplications(ctx *gin.Context) {
	pamPagination(ctx)
	doGet[*model.PAMApplication](ctx, true, pamApplications.Query(ctx), config.RESOURCE_PAM_APPLICATION)
}

func (c *Controller) CreatePAMApplication(ctx *gin.Context) {
	body, err := pamBody(ctx)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	application, err := pamApplications.Create(ctx, body)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(application))
}

func (c *Controller) UpdatePAMApplication(ctx *gin.Context) {
	body, err := pamBody(ctx)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	id := cast.ToInt(ctx.Param("id"))
	if id <= 0 {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	application, err := pamApplications.Update(ctx, id, body)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(application))
}

func (c *Controller) RetrievePAMApplicationCredential(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")
	if ctx.Request.URL.RawQuery != "" {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	body, err := pamBody(ctx)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	credential, err := pamApplications.Retrieve(ctx.Request.Context(), service.PAMBearerEvidence(ctx.GetHeader("Authorization")),
		ctx.Request.Method, ctx.Request.URL.Path, ctx.ClientIP(), body)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(credential))
}

func (c *Controller) DisablePAMApplication(ctx *gin.Context) {
	var input struct {
		Revision uint64 `json:"revision"`
	}
	if err := ctx.ShouldBindBodyWithJSON(&input); err != nil {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	id := cast.ToInt(ctx.Param("id"))
	if id <= 0 {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	application, err := pamApplications.Disable(ctx, id, input.Revision)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(application))
}

func (c *Controller) GetPAMTargets(ctx *gin.Context) {
	pamPagination(ctx)
	query, err := pamApplications.TargetQuery(ctx, ctx.Query("kind"))
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	doGet[*pamTargetSummary](ctx, false, query, "")
}

func (c *Controller) GetPAMCapabilities(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(map[string]any{
		"application_actions":        []string{acl.Retrieve},
		"application_target_kinds":   []string{model.PAMOwnerAccount},
		"policy_mfa_scope":           acl.PAMMFAPolicy,
		"managed_account_platforms":  service.PAMPlatforms(),
		"access_request_actions":     []string{"connect"},
		"access_policy_target_kinds": []string{model.PAMOwnerAccount},
		"approval_providers":         []string{model.PAMApprovalITSM},
		"session_limits_enabled":     true,
	}))
}

func (c *Controller) RetrievePAMHumanCredential(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")
	target := model.PAMCredentialTarget{Kind: ctx.Param("kind"), ID: cast.ToInt(ctx.Param("id"))}
	if target.ID <= 0 {
		abortPAM(ctx, service.ErrPAMInput)
		return
	}
	credential, err := service.RetrieveHumanCredential(ctx, target)
	if err != nil {
		abortPAM(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, NewHttpResponseWithData(credential))
}

func (c *Controller) GetPAMAccessAudit(ctx *gin.Context) {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil {
		abortPAM(ctx, service.ErrPAMDenied)
		return
	}
	pamPagination(ctx)
	query := db.GetDB().WithContext(ctx.Request.Context()).Model(&model.PAMAccessAudit{})
	if !acl.IsAdmin(operator) {
		resources, err := acl.GetRoleResources(ctx.Request.Context(), operator.GetRid(), config.RESOURCE_PAM_APPLICATION)
		if err != nil {
			abortPAM(ctx, service.ErrPAMUnavailable)
			return
		}
		resourceIDs := make([]int, 0, len(resources))
		for _, resource := range resources {
			for _, action := range resource.Permissions {
				if action == acl.READ {
					resourceIDs = append(resourceIDs, resource.ResourceId)
					break
				}
			}
		}
		applications := db.GetDB().Model(&model.PAMApplication{}).Select("id").Where("resource_id IN ?", resourceIDs)
		query = query.Where("(actor_type = ? AND acl_uid = ?) OR (actor_type = ? AND actor_id IN (?))", "user", operator.Uid, "application", applications)
	}
	query = db.FilterEqual(ctx, query, "actor_type", "actor_id", "target_kind", "target_id", "outcome")
	for _, bound := range []struct{ key, comparison string }{{"start", "created_at >= ?"}, {"end", "created_at <= ?"}} {
		if value := ctx.Query(bound.key); value != "" {
			parsed, err := time.Parse(time.RFC3339, value)
			if err != nil {
				abortPAM(ctx, service.ErrPAMInput)
				return
			}
			query = query.Where(bound.comparison, parsed)
		}
	}
	doGet[*model.PAMAccessAudit](ctx, false, query, "")
}
