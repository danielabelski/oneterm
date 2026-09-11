package service

import (
	"github.com/gin-gonic/gin"

	"github.com/veops/oneterm/internal/acl"
)

const (
	CredentialAccessAuditPermission = "credential_access_audit"
	PasswordViewAuditPermission     = "password_view_audit"
)

// Global audit pages require explicit operations; existing personal queries retain their scope.
func PAMAuditAll(ctx *gin.Context, operator *acl.Session, permission string) (bool, error) {
	if operator == nil || operator.Uid <= 0 {
		return false, ErrPAMDenied
	}
	switch ctx.Query("view") {
	case "":
		return acl.IsAdmin(operator), nil
	case "mine":
		return false, nil
	case "all":
	default:
		return false, ErrPAMInput
	}
	if acl.IsAdmin(operator) {
		return true, nil
	}
	resources, err := acl.GetRoleResources(ctx.Request.Context(), operator.GetRid(), "OperationPermission")
	if err != nil {
		return false, ErrPAMUnavailable
	}
	for _, resource := range resources {
		if resource.Name == "Audits" {
			for _, action := range resource.Permissions {
				if action == permission {
					return true, nil
				}
			}
		}
	}
	return false, ErrPAMDenied
}
