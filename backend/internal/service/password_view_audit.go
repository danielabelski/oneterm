package service

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/pkg/db"
)

type PasswordViewAuditEntry struct {
	model.PAMAccessAudit
	TargetName        string           `json:"target_name"`
	TargetUsername    string           `json:"target_username"`
	RequesterUID      int              `json:"requester_uid"`
	TicketID          int              `json:"ticket_id"`
	ITSMTemplateID    int              `json:"itsm_template_id"`
	RequestState      string           `json:"request_state"`
	EventState        string           `json:"event_state"`
	RequestReason     string           `json:"request_reason"`
	GrantedAt         *time.Time       `json:"granted_at"`
	GrantedUntil      *time.Time       `json:"granted_until"`
	GrantRevokedAt    *time.Time       `json:"grant_revoked_at"`
	GrantRevokeReason string           `json:"grant_revoke_reason"`
	ApproverUIDs      model.Slice[int] `json:"approver_uids"`
}

// Password audit joins the existing request and audit records; it does not scan ITSM history.
func PasswordViewAuditQuery(ctx *gin.Context) (*gorm.DB, error) {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil || operator.Uid <= 0 {
		return nil, ErrPAMDenied
	}
	all, err := PAMAuditAll(ctx, operator, PasswordViewAuditPermission)
	if err != nil {
		return nil, err
	}
	query := db.GetDB().WithContext(ctx.Request.Context()).Table("pam_access_audit AS audit").
		Select("audit.*, COALESCE(req.target_name, JSON_UNQUOTE(JSON_EXTRACT(audit.detail, '$.target_name')), account.name, gateway.name, '') AS target_name, "+
			"COALESCE(req.target_username, JSON_UNQUOTE(JSON_EXTRACT(audit.detail, '$.target_username')), account.account, gateway.account, '') AS target_username, "+
			"COALESCE(req.requester_uid, audit.acl_uid) AS requester_uid, req.ticket_id, req.itsm_template_id, req.state AS request_state, "+
			"JSON_UNQUOTE(JSON_EXTRACT(audit.detail, '$.state')) AS event_state, req.reason AS request_reason, "+
			"req.granted_at, req.granted_until, req.grant_revoked_at, req.grant_revoke_reason, req.approver_uids").
		Joins("LEFT JOIN pam_access_request AS req ON req.id = COALESCE(NULLIF(audit.access_request_id, ''), NULLIF(audit.grant_id, ''))").
		Joins("LEFT JOIN account ON audit.target_kind = ? AND account.id = audit.target_id AND (? OR audit.outcome = ?)", model.PAMOwnerAccount, all, "succeeded").
		Joins("LEFT JOIN gateway ON audit.target_kind = ? AND gateway.id = audit.target_id AND (? OR audit.outcome = ?)", model.PAMOwnerGateway, all, "succeeded").
		Where("audit.actor_type IN ? AND (audit.action = ? OR req.action = ?)", []string{"user", "system"}, acl.Retrieve, acl.Retrieve)
	if !all {
		query = query.Where("req.requester_uid = ? OR (audit.actor_type = ? AND audit.acl_uid = ?)", operator.Uid, "user", operator.Uid)
	}
	if search := strings.TrimSpace(ctx.Query("search")); search != "" {
		pattern := "%" + search + "%"
		query = query.Where("req.target_name LIKE ? OR req.target_username LIKE ? OR account.name LIKE ? OR account.account LIKE ? OR gateway.name LIKE ? OR gateway.account LIKE ?", pattern, pattern, pattern, pattern, pattern, pattern)
	}
	if outcome := ctx.Query("outcome"); outcome != "" {
		query = query.Where("audit.outcome = ?", outcome)
	}
	if action := ctx.Query("action"); action != "" {
		query = query.Where("audit.action = ?", action)
	}
	for _, bound := range []struct{ key, comparison string }{{"start", "audit.created_at >= ?"}, {"end", "audit.created_at <= ?"}} {
		if value := ctx.Query(bound.key); value != "" {
			parsed, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return nil, ErrPAMInput
			}
			query = query.Where(bound.comparison, parsed)
		}
	}
	return query, nil
}
