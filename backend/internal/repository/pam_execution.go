package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/pkg/secret"
)

var ErrPAMExecutionState = errors.New("PAM execution state or ownership changed")

type PAMExecutionRepository struct {
	database    *gorm.DB
	credentials *PAMCredentialRepository
}

func NewPAMExecutionRepository(database *gorm.DB, credentials *PAMCredentialRepository) *PAMExecutionRepository {
	return &PAMExecutionRepository{database: database, credentials: credentials}
}

// Prepare is called only after action authorization and scope approval. It publishes no active secret.
func (r *PAMExecutionRepository) Prepare(ctx context.Context, input model.PAMExecution, candidate secret.Material) (*model.PAMExecution, error) {
	if input.AccountID <= 0 || input.CreatorUID <= 0 || input.BindingID == 0 || input.AccountRevision == 0 ||
		input.BindingRevision == 0 || len(input.IntentHash) != 64 || input.IdempotencyKey == "" || len(input.IdempotencyKey) > 64 ||
		(input.Action != "rotate_secret" && input.Action != "recover_secret") || candidate.Kind() != secret.Password || candidate.PasswordValue() == "" {
		return nil, ErrPAMExecutionState
	}
	var execution *model.PAMExecution
	err := r.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var account model.Account
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("managed = ?", true).First(&account, input.AccountID).Error; err != nil {
			return err
		}
		var previous model.PAMExecution
		err := tx.Where("creator_uid = ? AND idempotency_key = ?", input.CreatorUID, input.IdempotencyKey).First(&previous).Error
		if err == nil {
			if previous.IntentHash != input.IntentHash || previous.AccountID != input.AccountID || previous.Action != input.Action {
				return ErrPAMExecutionState
			}
			execution = &previous
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if !account.Enabled || account.Revision != input.AccountRevision || account.CredentialVersionID != input.PreviousVersionID ||
			account.CredentialVersionID == "" || account.AccountType != model.AUTHMETHOD_PASSWORD {
			return ErrPAMExecutionState
		}
		var binding model.PAMAssetAccountBinding
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&binding, input.BindingID).Error; err != nil {
			return err
		}
		if !binding.Enabled || binding.AccountID != account.Id || binding.Revision != input.BindingRevision {
			return ErrPAMExecutionState
		}
		var asset model.Asset
		if err := tx.First(&asset, binding.AssetID).Error; err != nil {
			return err
		}
		if !BindingMatchesAsset(&binding, &asset) {
			return ErrPAMBindingChanged
		}
		execution = &model.PAMExecution{ID: uuid.NewString(), AccountID: account.Id, ActiveAccountID: &account.Id,
			CreatorUID: input.CreatorUID, IdempotencyKey: input.IdempotencyKey, IntentHash: input.IntentHash,
			ScopeHash: input.ScopeHash,
			Action:    input.Action, AccountRevision: account.Revision, BindingID: binding.ID, BindingRevision: binding.Revision,
			PreviousVersionID: account.CredentialVersionID, State: model.PAMExecutionPrepared, Revision: 1, SourceIP: input.SourceIP}
		if err := tx.Create(execution).Error; err != nil {
			return err
		}
		version, err := r.credentials.Stage(ctx, tx, model.PAMOwnerAccount, account.Id, input.CreatorUID, execution.ID, candidate)
		if err != nil {
			return err
		}
		execution.CandidateVersionID = version.ID
		if err := tx.Save(execution).Error; err != nil {
			return err
		}
		return tx.Create(&model.PAMAccessAudit{RequestID: execution.ID, ActorType: "user", ActorID: input.CreatorUID,
			ACLUID: input.CreatorUID, TargetKind: model.PAMOwnerAccount, TargetID: account.Id,
			Action: input.Action, Outcome: "pending", SourceIP: input.SourceIP, ExecutionID: execution.ID}).Error
	})
	if err != nil {
		return nil, err
	}
	return execution, nil
}

// Claim never restarts a possibly sent mutation. The caller must explicitly request reconciliation.
func (r *PAMExecutionRepository) Claim(ctx context.Context, id, owner string, reconcile bool) (*model.PAMExecution, error) {
	if id == "" || owner == "" || len(owner) > 64 {
		return nil, ErrPAMExecutionState
	}
	var execution model.PAMExecution
	err := r.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", id).First(&execution).Error; err != nil {
			return err
		}
		now := time.Now()
		if execution.ActiveAccountID == nil || (execution.LeaseUntil != nil && execution.LeaseUntil.After(now)) {
			return ErrPAMExecutionState
		}
		if (execution.State == model.PAMExecutionPrepared) == reconcile {
			return ErrPAMExecutionState
		}
		switch execution.State {
		case model.PAMExecutionPrepared, model.PAMExecutionChanging, model.PAMExecutionVerifying, model.PAMExecutionUnknown, model.PAMExecutionVerified:
		default:
			return ErrPAMExecutionState
		}
		if execution.State != model.PAMExecutionPrepared {
			execution.State = model.PAMExecutionUnknown
		}
		until := now.Add(2 * time.Minute)
		execution.LeaseOwner, execution.LeaseUntil, execution.Revision = owner, &until, execution.Revision+1
		return tx.Save(&execution).Error
	})
	return &execution, err
}

func (r *PAMExecutionRepository) withLease(ctx context.Context, id, owner string, fn func(*gorm.DB, *model.PAMExecution) error) error {
	if owner == "" {
		return ErrPAMExecutionState
	}
	var scope model.PAMExecution
	if err := r.database.WithContext(ctx).Select("id", "account_id").Where("id = ?", id).First(&scope).Error; err != nil {
		return err
	}
	return r.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Use the same account-first lock order as Prepare before touching the active-account unique index.
		var account model.Account
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("managed = ?", true).First(&account, scope.AccountID).Error; err != nil {
			return err
		}
		var execution model.PAMExecution
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", id).First(&execution).Error; err != nil {
			return err
		}
		if execution.LeaseOwner != owner || execution.LeaseUntil == nil || !execution.LeaseUntil.After(time.Now()) || execution.ActiveAccountID == nil {
			return ErrPAMExecutionState
		}
		return fn(tx, &execution)
	})
}

func (r *PAMExecutionRepository) BeforeChange(ctx context.Context, id, owner string) error {
	return r.withLease(ctx, id, owner, func(tx *gorm.DB, execution *model.PAMExecution) error {
		if execution.State != model.PAMExecutionPrepared {
			return ErrPAMExecutionState
		}
		var account model.Account
		if err := tx.Where("managed = ?", true).First(&account, execution.AccountID).Error; err != nil {
			return err
		}
		if !account.Enabled || account.Revision != execution.AccountRevision || account.CredentialVersionID != execution.PreviousVersionID {
			return ErrPAMExecutionState
		}
		var binding model.PAMAssetAccountBinding
		if err := tx.First(&binding, execution.BindingID).Error; err != nil {
			return err
		}
		if !binding.Enabled || binding.AccountID != account.Id || binding.Revision != execution.BindingRevision {
			return ErrPAMExecutionState
		}
		var asset model.Asset
		if err := tx.First(&asset, binding.AssetID).Error; err != nil {
			return err
		}
		if !BindingMatchesAsset(&binding, &asset) {
			return ErrPAMBindingChanged
		}
		// Recheck the durable candidate before recording a send; no external operation may precede this commit.
		if _, err := r.credentials.ReadCandidate(ctx, tx, model.PAMOwnerAccount, account.Id, execution.CandidateVersionID); err != nil {
			return err
		}
		now := time.Now()
		execution.State, execution.SendStartedAt, execution.Revision = model.PAMExecutionChanging, &now, execution.Revision+1
		return tx.Save(execution).Error
	})
}

func (r *PAMExecutionRepository) ChangeResult(ctx context.Context, id, owner string, changed bool) error {
	return r.withLease(ctx, id, owner, func(tx *gorm.DB, execution *model.PAMExecution) error {
		if execution.State != model.PAMExecutionChanging {
			return ErrPAMExecutionState
		}
		execution.State, execution.LastErrorCode = model.PAMExecutionUnknown, "result_unknown"
		if changed {
			execution.State, execution.LastErrorCode = model.PAMExecutionVerifying, ""
		}
		execution.Revision++
		return tx.Save(execution).Error
	})
}

func (r *PAMExecutionRepository) CandidateResult(ctx context.Context, id, owner string, verified bool) error {
	return r.withLease(ctx, id, owner, func(tx *gorm.DB, execution *model.PAMExecution) error {
		if execution.State != model.PAMExecutionVerifying && execution.State != model.PAMExecutionUnknown {
			return ErrPAMExecutionState
		}
		execution.State, execution.LastErrorCode = model.PAMExecutionUnknown, "candidate_not_verified"
		if verified {
			now := time.Now()
			execution.State, execution.VerifiedAt, execution.LastErrorCode = model.PAMExecutionVerified, &now, ""
		}
		execution.Revision++
		return tx.Save(execution).Error
	})
}

func (r *PAMExecutionRepository) Publish(ctx context.Context, id, owner string) error {
	var current model.PAMExecution
	if err := r.database.WithContext(ctx).Where("id = ?", id).First(&current).Error; err != nil {
		return err
	}
	if current.State == model.PAMExecutionComplete {
		return nil
	}
	return r.withLease(ctx, id, owner, func(tx *gorm.DB, execution *model.PAMExecution) error {
		if execution.State != model.PAMExecutionVerified || execution.VerifiedAt == nil {
			return ErrPAMExecutionState
		}
		var account model.Account
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("managed = ?", true).First(&account, execution.AccountID).Error; err != nil {
			return err
		}
		if err := r.credentials.Publish(ctx, tx, &account, execution.PreviousVersionID, execution.CandidateVersionID); err != nil {
			return err
		}
		now := time.Now()
		execution.State, execution.FinishedAt, execution.LastErrorCode = model.PAMExecutionComplete, &now, ""
		execution.ActiveAccountID, execution.LeaseOwner, execution.LeaseUntil = nil, "", nil
		execution.Revision++
		if err := tx.Save(execution).Error; err != nil {
			return err
		}
		result := tx.Model(&model.PAMAccessAudit{}).Where("request_id = ?", execution.ID).Updates(map[string]any{
			"outcome": "succeeded", "finished_at": now, "version_id": execution.CandidateVersionID,
		})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrPAMExecutionState
		}
		return nil
	})
}

// FinishUnsent is used only when the current executor confirms it never invoked the mutation.
func (r *PAMExecutionRepository) FinishUnsent(ctx context.Context, id, owner, code string) error {
	return r.finishUnchanged(ctx, id, owner, code, false)
}

// RejectChange requires an explicit server rejection of the mutation, not a timeout or lost response.
func (r *PAMExecutionRepository) RejectChange(ctx context.Context, id, owner, code string) error {
	return r.finishUnchanged(ctx, id, owner, code, true)
}

func (r *PAMExecutionRepository) finishUnchanged(ctx context.Context, id, owner, code string, sent bool) error {
	if code == "" || len(code) > 64 {
		return ErrPAMExecutionState
	}
	return r.withLease(ctx, id, owner, func(tx *gorm.DB, execution *model.PAMExecution) error {
		if execution.State != model.PAMExecutionPrepared && execution.State != model.PAMExecutionChanging {
			return ErrPAMExecutionState
		}
		if sent && execution.State != model.PAMExecutionChanging {
			return ErrPAMExecutionState
		}
		now := time.Now()
		execution.State, execution.LastErrorCode, execution.FinishedAt = model.PAMExecutionFailed, code, &now
		execution.ActiveAccountID, execution.LeaseOwner, execution.LeaseUntil = nil, "", nil
		execution.Revision++
		if err := tx.Save(execution).Error; err != nil {
			return err
		}
		result := tx.Model(&model.PAMAccessAudit{}).Where("request_id = ?", execution.ID).Updates(map[string]any{
			"outcome": "failed", "reason_code": code, "finished_at": now,
		})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrPAMExecutionState
		}
		return nil
	})
}

// PreserveOriginal follows explicit operator confirmation and successful authentication with the original version.
// The candidate is retained, not destroyed: this does not claim to revoke other credentials on the remote system.
func (r *PAMExecutionRepository) PreserveOriginal(ctx context.Context, id, owner string) error {
	return r.withLease(ctx, id, owner, func(tx *gorm.DB, execution *model.PAMExecution) error {
		if execution.State != model.PAMExecutionUnknown {
			return ErrPAMExecutionState
		}
		var account model.Account
		if err := tx.Where("managed = ?", true).First(&account, execution.AccountID).Error; err != nil {
			return err
		}
		if account.CredentialVersionID != execution.PreviousVersionID {
			return ErrPAMExecutionState
		}
		version := tx.Model(&model.PAMCredentialVersion{}).Where("id = ? AND owner_kind = ? AND owner_id = ? AND state = ?",
			execution.CandidateVersionID, model.PAMOwnerAccount, account.Id, model.PAMVersionPending).
			Update("state", model.PAMVersionRetained)
		if version.Error != nil {
			return version.Error
		}
		if version.RowsAffected != 1 {
			return ErrPAMExecutionState
		}
		now := time.Now()
		execution.State, execution.LastErrorCode, execution.FinishedAt = model.PAMExecutionFailed, "original_verified", &now
		execution.ActiveAccountID, execution.LeaseOwner, execution.LeaseUntil = nil, "", nil
		execution.Revision++
		if err := tx.Save(execution).Error; err != nil {
			return err
		}
		audit := tx.Model(&model.PAMAccessAudit{}).Where("request_id = ?", id).Updates(map[string]any{
			"outcome": "failed", "reason_code": "original_verified", "finished_at": now,
		})
		if audit.Error != nil {
			return audit.Error
		}
		if audit.RowsAffected != 1 {
			return ErrPAMExecutionState
		}
		return nil
	})
}
