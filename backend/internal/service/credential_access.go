package service

import (
	"context"
	"errors"
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

func finishPAMAccessAudit(ctx context.Context, repo *repository.PAMApplicationRepository, audit *model.PAMAccessAudit, operationErr error) error {
	audit.Outcome, audit.ReasonCode = "succeeded", ""
	if operationErr != nil {
		audit.Outcome, audit.ReasonCode = "denied", "not_permitted"
		switch {
		case errors.Is(operationErr, ErrPAMMFARequired):
			audit.ReasonCode = "mfa_required"
		case errors.Is(operationErr, ErrPAMReplay):
			audit.ReasonCode = "evidence_replayed"
		case errors.Is(operationErr, ErrPAMApprovalRequired):
			audit.ReasonCode = "approval_required"
		case errors.Is(operationErr, ErrPAMUnavailable), errors.Is(operationErr, acl.ErrIdentityUnavailable):
			audit.Outcome, audit.ReasonCode = "failed", "storage_unavailable"
		}
	}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := repo.FinishAudit(auditCtx, audit); err != nil {
		return ErrPAMUnavailable
	}
	return nil
}

func RetrieveHumanCredential(ctx *gin.Context, target model.PAMCredentialTarget) (response *PAMCredentialResponse, err error) {
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
	standing, err := pamResourcePermission(requestCtx, operator, owner, acl.Retrieve, true)
	if err != nil {
		return nil, ErrPAMUnavailable
	}
	if !standing {
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
			grant, err := authorizePasswordView(tx, current, policy, operator, passwordViewRights{Direct: standing})
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
			if grant != nil {
				audit.GrantID = grant.ID
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}
