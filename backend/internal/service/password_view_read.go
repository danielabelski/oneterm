package service

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	"github.com/veops/oneterm/pkg/config"
	"github.com/veops/oneterm/pkg/db"
)

const PasswordViewRequestPermission = "request_retrieve"

type passwordViewRights struct {
	Admin   bool
	Direct  bool
	Request bool
}

func (r passwordViewRights) eligible(policy *model.PAMPolicy) bool {
	return r.Admin || r.Direct || (r.Request && requiresPAMApproval(policy, acl.Retrieve))
}

func (r passwordViewRights) needsApproval(policy *model.PAMPolicy) bool {
	return r.canRequest() && requiresPAMApproval(policy, acl.Retrieve)
}

func (r passwordViewRights) canRequest() bool {
	return r.Request && !r.Admin && !r.Direct
}

// Request eligibility is an account ACL action, independent of asset or connection permissions.
func loadPasswordViewRights(ctx context.Context, operator *acl.Session, owner model.CredentialOwner) (passwordViewRights, error) {
	rights := passwordViewRights{}
	if operator == nil || operator.Uid <= 0 {
		return rights, ErrPAMDenied
	}
	rights.Admin = acl.IsAdmin(operator)
	if rights.Admin {
		return rights, nil
	}
	var err error
	rights.Direct, err = pamResourcePermission(ctx, operator, owner, acl.Retrieve, false)
	if err == nil && !rights.Direct {
		rights.Request, err = pamResourcePermission(ctx, operator, owner, PasswordViewRequestPermission, false)
	}
	return rights, err
}

// This endpoint admits request-only users; legacy, machine and connection readers are unchanged.
func RetrievePasswordView(ctx *gin.Context, target model.PAMCredentialTarget) (response *PAMCredentialResponse, err error) {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil || operator.Uid <= 0 {
		return nil, ErrPAMDenied
	}
	requestCtx, cancel := context.WithTimeout(ctx.Request.Context(), 10*time.Second)
	defer cancel()
	repo := repository.NewPAMApplicationRepository()
	audit := &model.PAMAccessAudit{RequestID: uuid.NewString(), ActorType: "user", ActorID: operator.Uid,
		ACLUID: operator.Uid, TargetKind: target.Kind, TargetID: target.ID, Action: acl.Retrieve,
		Outcome: "pending", SourceIP: ctx.ClientIP()}
	if err := repo.BeginAudit(requestCtx, audit); err != nil {
		return nil, ErrPAMUnavailable
	}
	defer func() {
		if auditErr := finishPAMAccessAudit(requestCtx, repo, audit, err); auditErr != nil {
			response, err = nil, auditErr
		}
	}()
	owner, err := repository.LoadCredentialOwner(requestCtx, db.GetDB(), target)
	if err != nil {
		return nil, ErrPAMDenied
	}
	rights, err := loadPasswordViewRights(requestCtx, operator, owner)
	if err != nil {
		return nil, ErrPAMUnavailable
	}
	if !rights.Admin && !rights.Direct && !rights.Request {
		return nil, ErrPAMDenied
	}
	if !acl.VerifyMFAToken(requestCtx, operator, ctx.GetHeader("X-MFA-Token"), acl.PAMMFARetrieve) {
		return nil, ErrPAMMFARequired
	}
	credentials, err := repository.ConfiguredCredentials()
	if err != nil {
		return nil, ErrPAMUnavailable
	}
	err = db.GetDB().WithContext(requestCtx).Transaction(func(tx *gorm.DB) error {
		return repository.WithPAMActionPolicy(tx, target, acl.Retrieve, "SHARE", func(tx *gorm.DB, current model.CredentialOwner, policy *model.PAMPolicy) error {
			if current.GetResourceId() != owner.GetResourceId() {
				return ErrPAMScopeChanged
			}
			// Evaluate the current locked policy: disabling approval never turns request permission into retrieval.
			grant, err := authorizePasswordView(tx, current, policy, operator, rights)
			if err != nil {
				return err
			}
			material, err := credentials.ResolveInTransaction(requestCtx, tx, current, []byte(config.Cfg.Auth.Aes.Iv))
			if err != nil {
				return ErrPAMUnavailable
			}
			response = credentialResponse(current)
			response.Password, response.PK, response.Phrase = material.PasswordValue(), material.PrivateKeyValue(), material.PassphraseValue()
			audit.VersionID = current.CredentialReference()
			audit.Detail = model.Map[string, any]{"target_name": current.GetName(), "target_username": response.Account}
			if grant != nil {
				audit.GrantID, audit.AccessRequestID = grant.ID, grant.RequestID
			}
			result := tx.Model(&model.PAMAccessAudit{}).Where("id = ? AND outcome = ?", audit.Id, "pending").
				Updates(map[string]any{"access_request_id": audit.AccessRequestID, "detail": audit.Detail})
			if result.Error != nil || result.RowsAffected != 1 {
				return ErrPAMUnavailable
			}
			return nil
		})
	})
	return response, err
}
