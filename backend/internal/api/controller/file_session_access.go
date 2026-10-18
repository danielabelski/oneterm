package controller

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/veops/oneterm/internal/acl"
	fileservice "github.com/veops/oneterm/internal/service/file"
	gsession "github.com/veops/oneterm/internal/session"
)

// Session ownership does not replace per-action authorization.
func canAccessFileSession(ctx *gin.Context, session *gsession.Session) bool {
	operator, err := acl.GetSessionFromCtx(ctx)
	return err == nil && operator != nil && operator.GetUid() > 0 && session != nil && session.Session != nil &&
		(operator.GetUid() == session.Uid || acl.IsAdmin(operator))
}

func registerFileProgress(ctx *gin.Context, id, kind, scope string, active bool) bool {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil || operator == nil || operator.Uid <= 0 {
		ctx.AbortWithStatus(http.StatusForbidden)
		return false
	}
	if err := fileservice.CreateTransferProgress(id, kind, operator.Uid, scope, active); err != nil {
		status := http.StatusConflict
		if errors.Is(err, fileservice.ErrTransferProgressInput) {
			status = http.StatusBadRequest
		}
		if errors.Is(err, fileservice.ErrTransferProgressCapacity) {
			status = http.StatusServiceUnavailable
		}
		ctx.JSON(status, gin.H{"code": status, "message": "Transfer progress is unavailable"})
		return false
	}
	return true
}
