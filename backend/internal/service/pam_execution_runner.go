package service

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	"github.com/veops/oneterm/pkg/db"
	"github.com/veops/oneterm/pkg/secret"
)

// These callbacks are constructed by the authorized service from a fixed target, never from request scripts.
type PAMExecutionAuthorize func(context.Context, *model.PAMExecution) error
type PAMExecutionChange func(context.Context, secret.Material, secret.Material, PAMBeforeChange) PAMExecutionResult
type PAMExecutionVerify func(context.Context, secret.Material) PAMExecutionResult

// RunPAMExecution coordinates existing storage and the two platform executors without a long database transaction.
// Reconciliation verifies the saved candidate once. It never tries the previous password or repeats a mutation.
func RunPAMExecution(ctx context.Context, id string, reconcile bool, authorize PAMExecutionAuthorize,
	change PAMExecutionChange, verify PAMExecutionVerify) (PAMExecutionResult, error) {
	if authorize == nil || change == nil || verify == nil {
		return PAMExecutionResult{}, ErrPAMInput
	}
	var scope model.PAMExecution
	if err := db.GetDB().WithContext(ctx).Where("id = ?", id).First(&scope).Error; err != nil {
		return PAMExecutionResult{}, err
	}
	if err := authorize(ctx, &scope); err != nil {
		return PAMExecutionResult{Code: PAMExecutionDenied}, err
	}
	credentials, err := repository.ConfiguredCredentials()
	if err != nil {
		return PAMExecutionResult{}, err
	}
	store := repository.NewPAMExecutionRepository(db.GetDB(), credentials)
	owner := uuid.NewString()
	execution, err := store.Claim(ctx, id, owner, reconcile)
	if err != nil {
		return PAMExecutionResult{}, err
	}
	if err := authorize(ctx, execution); err != nil {
		if execution.State == model.PAMExecutionPrepared {
			if saveErr := store.FinishUnsent(ctx, id, owner, string(PAMExecutionDenied)); saveErr != nil {
				return PAMExecutionResult{}, saveErr
			}
		}
		return PAMExecutionResult{Code: PAMExecutionDenied}, err
	}
	candidate, err := credentials.ReadCandidate(ctx, db.GetDB(), model.PAMOwnerAccount, execution.AccountID, execution.CandidateVersionID)
	if err != nil {
		return PAMExecutionResult{}, err
	}
	if execution.State == model.PAMExecutionPrepared {
		current, err := credentials.ReadActive(ctx, model.PAMOwnerAccount, execution.AccountID, execution.PreviousVersionID)
		if err != nil {
			return PAMExecutionResult{}, err
		}
		result := change(ctx, current, candidate, func(ctx context.Context) error {
			if err := authorize(ctx, execution); err != nil {
				return err
			}
			return store.BeforeChange(ctx, id, owner)
		})
		// Retain the result even when the triggering HTTP request or worker context was cancelled.
		saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		if !result.Attempted {
			err = store.FinishUnsent(saveCtx, id, owner, string(result.Code))
			cancel()
			return result, err
		}
		if result.ConfirmedUnchanged {
			err = store.RejectChange(saveCtx, id, owner, string(result.Code))
			cancel()
			return result, err
		}
		err = store.ChangeResult(saveCtx, id, owner, result.Code == PAMExecutionChanged)
		cancel()
		if err != nil || result.Code != PAMExecutionChanged {
			return result, err
		}
	}
	result := verify(ctx, candidate)
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := store.CandidateResult(saveCtx, id, owner, result.Code == PAMExecutionVerified); err != nil {
		return result, err
	}
	if result.Code != PAMExecutionVerified {
		return result, nil
	}
	if err := store.Publish(saveCtx, id, owner); err != nil {
		return result, err
	}
	return result, nil
}
