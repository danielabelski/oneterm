package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cast"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/service"
	"github.com/veops/oneterm/pkg/errors"
)

var (
	shareService = service.NewShareService()
)

// CreateShare godoc
//
//	@Tags		share
//	@Param		share	body		[]model.Share	true	"share"
//	@Success	200		{object}	HttpResponse{data=ListData{list=[]string}}
//	@Router		/share [post]
func (c *Controller) CreateShare(ctx *gin.Context) {
	currentUser, _ := acl.GetSessionFromCtx(ctx)
	var input []struct {
		model.Share
		RequireLogin *bool `json:"require_login"`
	}
	shares := make([]*model.Share, 0)

	if err := ctx.ShouldBindBodyWithJSON(&input); err != nil || len(input) == 0 {
		ctx.AbortWithError(http.StatusBadRequest, &errors.ApiError{Code: errors.ErrInvalidArgument, Data: map[string]any{"err": err}})
		return
	}
	for i := range input {
		share := &input[i].Share
		share.RequireLogin = input[i].RequireLogin == nil || *input[i].RequireLogin
		shares = append(shares, share)
	}

	for _, s := range shares {
		if !shareService.HasPermission(ctx, s, acl.GRANT) {
			ctx.AbortWithError(http.StatusForbidden, &errors.ApiError{Code: errors.ErrNoPerm, Data: map[string]any{"perm": acl.GRANT}})
			return
		}
		s.CreatorId = currentUser.GetUid()
		s.UpdaterId = currentUser.GetUid()
	}

	uuids, err := shareService.CreateShares(ctx, shares)
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, &errors.ApiError{Code: errors.ErrInternal, Data: map[string]any{"err": err}})
		return
	}

	ctx.JSON(http.StatusOK, toListData(uuids))
}

// DeleteShare godoc
//
//	@Tags		share
//	@Param		id	path		int	true	"share id"
//	@Success	200	{object}	HttpResponse
//	@Router		/share/:id [delete]
func (c *Controller) DeleteShare(ctx *gin.Context) {
	id := cast.ToInt(ctx.Param("id"))
	share, err := shareService.GetShareByID(ctx, id)
	if err != nil {
		ctx.AbortWithError(http.StatusBadRequest, &errors.ApiError{Code: errors.ErrInvalidArgument, Data: map[string]any{"err": err}})
		return
	}

	if !shareService.HasPermission(ctx, share, acl.GRANT) {
		ctx.AbortWithError(http.StatusForbidden, &errors.ApiError{Code: errors.ErrNoPerm, Data: map[string]any{"perm": acl.GRANT}})
		return
	}

	doDelete(ctx, false, &model.Share{}, "")
}

// GetShare godoc
//
//	@Tags		share
//	@Param		page_index	query		int		true	"page_index"
//	@Param		page_size	query		int		true	"page_size"
//	@Param		search		query		string	false	"name or ip"
//	@Param		start		query		string	false	"start, RFC3339"
//	@Param		end			query		string	false	"end, RFC3339"
//	@Param		asset_id	query		string	false	"asset id"
//	@Param		account_id	query		string	false	"account id"
//	@Success	200			{object}	HttpResponse{data=ListData{list=[]model.Share}}
//	@Router		/share [get]
func (c *Controller) GetShare(ctx *gin.Context) {
	currentUser, _ := acl.GetSessionFromCtx(ctx)
	isAdmin := acl.IsAdmin(currentUser)

	db, err := shareService.BuildQuery(ctx, isAdmin)
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, &errors.ApiError{Code: errors.ErrInternal, Data: map[string]any{"err": err}})
		return
	}

	doGet[*model.Share](ctx, false, db, "")
}

// ConnectShare godoc
//
//	@Tags		share
//	@Success	200	{object}	HttpResponse
//	@Param		w	query		int	false	"width"
//	@Param		h	query		int	false	"height"
//	@Param		dpi	query		int	false	"dpi"
//	@Success	200	{object}	HttpResponse{}
//	@Router		/share/connect/:uuid [get]
func (c *Controller) ConnectShare(ctx *gin.Context) {
	setShareOperator(ctx)
	uuid := ctx.Param("uuid")
	share, err := shareService.ValidateShareForConnection(ctx, uuid)
	if err == service.ErrShareLoginRequired {
		ctx.AbortWithError(http.StatusUnauthorized, &errors.ApiError{Code: errors.ErrUnauthorized})
		return
	}
	if err != nil {
		ctx.Set("shareErr", &errors.ApiError{Code: errors.ErrInvalidArgument, Data: map[string]any{"err": err}})
		c.Connect(ctx)
		return
	}

	shareService.SetupConnectionParams(ctx, share)
	c.Connect(ctx)
}

func setShareOperator(ctx *gin.Context) {
	operator := &acl.Session{Acl: acl.Acl{UserName: "Anonymous"}}
	if cookie, err := ctx.Cookie("session"); err == nil && cookie != "" {
		if authenticated, err := acl.ParseCookie(cookie); err == nil && authenticated != nil && authenticated.GetUid() > 0 {
			operator = authenticated
		}
	}
	ctx.Set("session", operator)
}

func shareOperatorAuthenticated(ctx *gin.Context) bool {
	operator, err := acl.GetSessionFromCtx(ctx)
	return err == nil && operator != nil && operator.GetUid() > 0
}

func (c *Controller) GetShareConnectionInfo(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")
	share, err := shareService.GetAvailableShare(ctx, ctx.Param("uuid"))
	if err != nil {
		ctx.AbortWithStatus(http.StatusNotFound)
		return
	}
	setShareOperator(ctx)
	ctx.JSON(http.StatusOK, HttpResponse{Data: map[string]bool{
		"require_login": share.RequireLogin,
		"authenticated": shareOperatorAuthenticated(ctx),
	}})
}
