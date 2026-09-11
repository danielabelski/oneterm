package service

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	"github.com/veops/oneterm/pkg/config"
	"github.com/veops/oneterm/pkg/db"
)

type PAMAdoptInput struct {
	AssetID         int    `json:"asset_id"`
	AccountID       int    `json:"account_id"`
	AuthorityKind   string `json:"authority_kind"`
	AuthorityRef    string `json:"authority_ref"`
	Platform        string `json:"platform"`
	NativeQualifier string `json:"native_qualifier"`
}

type PAMBindingInput struct {
	AssetID   int    `json:"asset_id"`
	AccountID int    `json:"account_id"`
	Revision  uint64 `json:"revision"`
	Enabled   bool   `json:"enabled"`
}

type PAMAccountService struct {
	repo *repository.PAMAccountRepository
}

func NewPAMAccountService() *PAMAccountService {
	return &PAMAccountService{repo: repository.NewPAMAccountRepository()}
}

func ParsePAMAdoption(body []byte) (*PAMAdoptInput, error) {
	var input PAMAdoptInput
	if err := decodePAMRequest(body, &input); err != nil {
		return nil, err
	}
	if input.AssetID <= 0 || input.AccountID <= 0 {
		return nil, ErrPAMInput
	}
	return &input, nil
}

func validatePAMAdoption(input *PAMAdoptInput, asset *model.Asset, source *model.Account) error {
	if input.AuthorityKind == "" {
		input.AuthorityKind = model.PAMAuthorityAsset
	}
	if utf8.RuneCountInString(source.Name) > 128 || source.Account == "" || asset.Ip == "" || utf8.RuneCountInString(source.Account) > 255 {
		return ErrPAMInput
	}
	switch input.AuthorityKind {
	case model.PAMAuthorityAsset:
		input.AuthorityRef = fmt.Sprintf("asset:%d", asset.Id)
	case model.PAMAuthorityShared:
		input.AuthorityRef = strings.TrimSpace(input.AuthorityRef)
		if input.AuthorityRef == "" || utf8.RuneCountInString(input.AuthorityRef) > 128 {
			return ErrPAMInput
		}
	default:
		return ErrPAMInput
	}
	protocols := make(map[string]bool)
	for _, protocol := range asset.Protocols {
		protocols[strings.SplitN(protocol, ":", 2)[0]] = true
	}
	platform, exists := PAMPlatform(input.Platform)
	if !exists || utf8.RuneCountInString(input.NativeQualifier) > 255 || !platformSupportsBinding(platform, input.AuthorityKind, source.AccountType, input.NativeQualifier, protocols) {
		return ErrPAMInput
	}
	return nil
}

// Adopt enables password management on the existing account, preserving its ID, ACL resource and credential.
func (s *PAMAccountService) Adopt(ctx *gin.Context, input *PAMAdoptInput, operator *acl.Session) (*model.Account, error) {
	if input == nil || operator == nil || operator.Uid <= 0 {
		return nil, ErrPAMDenied
	}
	var account *model.Account
	err := s.repo.Transaction(ctx.Request.Context(), func(tx *gorm.DB) error {
		asset, source, err := repository.LoadPAMAdoptionSource(ctx.Request.Context(), tx, input.AssetID, input.AccountID)
		if err != nil {
			return err
		}
		if source.Managed {
			return ErrPAMRevision
		}
		if err := validatePAMAdoption(input, asset, source); err != nil {
			return err
		}
		if input.AuthorityKind == model.PAMAuthorityAsset {
			if err := validatePAMAccountScope(ctx.Request.Context(), tx, source, asset.Id); err != nil {
				return err
			}
		}
		before := *source
		source.Managed, source.Enabled = true, true
		source.AuthorityKind, source.AuthorityRef = input.AuthorityKind, input.AuthorityRef
		source.NativeQualifier, source.Platform = input.NativeQualifier, input.Platform
		source.NativeKey = repository.PAMNativeKey(input.AuthorityKind, input.AuthorityRef, source.Account, input.NativeQualifier)
		source.Revision, source.UpdaterId = source.Revision+1, operator.Uid
		if input.AuthorityKind == model.PAMAuthorityAsset {
			source.AuthorityAssetID = asset.Id
		}
		if source.CredentialReference() == "" {
			credentials, err := repository.ConfiguredCredentials()
			if err != nil {
				return err
			}
			material, err := credentials.ResolveInTransaction(ctx.Request.Context(), tx, source, []byte(config.Cfg.Auth.Aes.Iv))
			if err != nil {
				return err
			}
			version, err := credentials.Stage(ctx.Request.Context(), tx, model.PAMOwnerAccount, source.Id, operator.Uid, "", material)
			if err != nil {
				return err
			}
			if err := credentials.Publish(ctx.Request.Context(), tx, source, "", version.ID); err != nil {
				return err
			}
			source.SetCredentialReference(version.ID)
		}
		if err := tx.Model(source).Select("managed", "enabled", "authority_kind", "authority_ref", "authority_asset_id",
			"native_qualifier", "native_key", "platform", "revision", "updater_id", "updated_at").Updates(source).Error; err != nil {
			return err
		}
		if err := tx.Create(repository.NewPAMBinding(asset, source, operator.Uid)).Error; err != nil {
			return err
		}
		history := NewHistoryService().CreateHistoryRecord(ctx, model.ACTION_UPDATE, source, &before, operator.Uid)
		history.New["password_management_enabled"] = true
		if err := tx.Create(history).Error; err != nil {
			return err
		}
		if err := tx.First(source, source.Id).Error; err != nil {
			return err
		}
		account = source
		return nil
	})
	if err != nil {
		return nil, err
	}
	repository.DeleteAllFromCacheDb(ctx, account)
	account.SetCredentialValues("", "", "")
	return account, nil
}

func (s *PAMAccountService) Get(ctx context.Context, id int) (*model.Account, error) {
	account, err := s.repo.Get(ctx, id)
	if account != nil {
		account.SetCredentialValues("", "", "")
	}
	return account, err
}

func (s *PAMAccountService) Query(ctx *gin.Context) *gorm.DB {
	query := s.repo.Query(ctx.Request.Context())
	if search := strings.TrimSpace(ctx.Query("search")); search != "" {
		query = query.Where("name LIKE ? OR account LIKE ?", "%"+search+"%", "%"+search+"%")
	}
	if platform := ctx.Query("platform"); platform != "" {
		query = query.Where("platform = ?", platform)
	}
	return query.Omit(CredentialStorageFields...)
}

func (s *PAMAccountService) Bindings(ctx context.Context, id int) *gorm.DB {
	return s.repo.Bindings(ctx, id)
}

func (s *PAMAccountService) AdoptionAssets(ctx *gin.Context) (*gorm.DB, error) {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil || operator.Uid <= 0 {
		return nil, ErrPAMDenied
	}
	query := db.GetDB().WithContext(ctx.Request.Context()).Model(&model.Asset{}).Select("id", "name", "ip", "protocols")
	if !acl.IsAdmin(operator) {
		_, assets, _, err := getNodeAssetAccoutIdsByAction(ctx, acl.GRANT)
		if err != nil {
			return nil, ErrPAMUnavailable
		}
		query = query.Where("id IN ?", assets)
	}
	if search := ctx.Query("search"); search != "" {
		query = query.Where("name LIKE ? OR ip LIKE ?", "%"+search+"%", "%"+search+"%")
	}
	return query, nil
}

func bindingCanAttach(managed *model.Account, asset *model.Asset, source *model.Account) bool {
	platform, exists := PAMPlatform(managed.Platform)
	protocols := make(map[string]bool)
	for _, protocol := range asset.Protocols {
		protocols[strings.SplitN(protocol, ":", 2)[0]] = true
	}
	if !exists || !platformSupportsBinding(platform, managed.AuthorityKind, managed.AccountType, managed.NativeQualifier, protocols) {
		return false
	}
	return managed.Managed && managed.Id == source.Id && managed.Enabled && managed.Account == source.Account && managed.AccountType == source.AccountType &&
		(managed.AuthorityKind == model.PAMAuthorityShared || managed.AuthorityAssetID == asset.Id)
}

func (s *PAMAccountService) Attach(ctx *gin.Context, id int, input PAMBindingInput, operator *acl.Session) (*model.PAMAssetAccountBinding, error) {
	var binding *model.PAMAssetAccountBinding
	err := s.repo.Transaction(ctx.Request.Context(), func(tx *gorm.DB) error {
		asset, source, err := repository.LoadPAMAdoptionSource(ctx.Request.Context(), tx, input.AssetID, input.AccountID)
		if err != nil {
			return err
		}
		var managed model.Account
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("managed = ?", true).First(&managed, id).Error; err != nil {
			return err
		}
		if !bindingCanAttach(&managed, asset, source) {
			return ErrPAMInput
		}
		binding = repository.NewPAMBinding(asset, &managed, operator.Uid)
		if err := tx.Create(binding).Error; err != nil {
			return err
		}
		history := NewHistoryService().CreateHistoryRecord(ctx, model.ACTION_UPDATE, &managed, &managed, operator.Uid)
		history.New["binding_added"] = map[string]any{"asset_id": asset.Id, "account_id": source.Id, "binding_id": binding.ID}
		return tx.Create(history).Error
	})
	return binding, err
}

func (s *PAMAccountService) Disable(ctx *gin.Context, id int, revision uint64, operator *acl.Session) (*model.Account, error) {
	return s.SetEnabled(ctx, id, revision, false, operator)
}

// RemoveManagement releases only PAM configuration; the account and its credential remain unchanged.
func (s *PAMAccountService) RemoveManagement(ctx *gin.Context, id int, revision uint64, operator *acl.Session) error {
	if revision == 0 || operator == nil || operator.Uid <= 0 {
		return ErrPAMInput
	}
	err := s.repo.Transaction(ctx.Request.Context(), func(tx *gorm.DB) error {
		var current model.Account
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("managed = ?", true).First(&current, id).Error; err != nil {
			return err
		}
		if current.Revision != revision {
			return ErrPAMRevision
		}
		var active int64
		if err := tx.Model(&model.PAMExecution{}).Where("active_account_id = ?", id).Count(&active).Error; err != nil {
			return err
		}
		if active != 0 {
			return repository.ErrPAMExecutionState
		}
		before := current
		if err := tx.Model(&model.PAMAccessRequest{}).
			Where("target_kind = ? AND target_id = ? AND action = ? AND state IN ?", model.PAMOwnerAccount, id, "connect", []string{model.PAMRequestPending, model.PAMRequestApproved}).
			Updates(map[string]any{"state": model.PAMRequestInvalidated, "revision": gorm.Expr("revision + 1"),
				"grant_revoked_at": time.Now(), "grant_revoker_uid": operator.Uid, "grant_revoke_reason": "management_removed",
				"sync_state": "pending", "sync_next_at": time.Now(), "sync_lease_owner": "", "sync_lease_until": nil}).Error; err != nil {
			return err
		}
		if err := tx.Where("account_id = ?", id).Delete(&model.PAMAssetAccountBinding{}).Error; err != nil {
			return err
		}
		if err := tx.Where("target_kind = ? AND target_id = ?", model.PAMOwnerAccount, id).Delete(&model.PAMPolicy{}).Error; err != nil {
			return err
		}
		if err := tx.Model(&current).Updates(map[string]any{"managed": false, "enabled": true, "platform": "",
			"authority_kind": "", "authority_ref": "", "authority_asset_id": 0, "native_key": nil,
			"native_qualifier": "", "revision": current.Revision + 1, "updater_id": operator.Uid}).Error; err != nil {
			return err
		}
		history := NewHistoryService().CreateHistoryRecord(ctx, model.ACTION_UPDATE, &current, &before, operator.Uid)
		history.New["password_management_removed"] = true
		return tx.Create(history).Error
	})
	if err == nil {
		repository.DeleteAllFromCacheDb(ctx, &model.Account{Id: id})
	}
	return err
}

func (s *PAMAccountService) SetEnabled(ctx *gin.Context, id int, revision uint64, enabled bool, operator *acl.Session) (*model.Account, error) {
	if revision == 0 {
		return nil, ErrPAMInput
	}
	var updated *model.Account
	err := s.repo.Transaction(ctx.Request.Context(), func(tx *gorm.DB) error {
		var current model.Account
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("managed = ?", true).First(&current, id).Error; err != nil {
			return err
		}
		if current.Revision != revision {
			return ErrPAMRevision
		}
		copy := current
		updated = &copy
		if current.Enabled == enabled {
			return nil
		}
		if enabled && current.AuthorityKind == model.PAMAuthorityAsset {
			var count int64
			if err := tx.Model(&model.Asset{}).Where("id = ?", current.AuthorityAssetID).Count(&count).Error; err != nil {
				return err
			}
			if count != 1 {
				return ErrPAMInput
			}
		}
		updated.Enabled, updated.Revision, updated.UpdaterId = enabled, current.Revision+1, operator.Uid
		if err := tx.Select("enabled", "revision", "updater_id", "updated_at").Save(updated).Error; err != nil {
			return err
		}
		return tx.Create(NewHistoryService().CreateHistoryRecord(ctx, model.ACTION_UPDATE, updated, &current, operator.Uid)).Error
	})
	if updated != nil {
		updated.SetCredentialValues("", "", "")
		repository.DeleteAllFromCacheDb(ctx, updated)
	}
	return updated, err
}

func (s *PAMAccountService) ReviewBinding(ctx *gin.Context, id int, input PAMBindingInput, operator *acl.Session) (*model.PAMAssetAccountBinding, error) {
	if input.Revision == 0 {
		return nil, ErrPAMInput
	}
	var updated *model.PAMAssetAccountBinding
	err := s.repo.Transaction(ctx.Request.Context(), func(tx *gorm.DB) error {
		asset, source, err := repository.LoadPAMAdoptionSource(ctx.Request.Context(), tx, input.AssetID, input.AccountID)
		if err != nil {
			return err
		}
		var managed model.Account
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("managed = ?", true).First(&managed, id).Error; err != nil {
			return err
		}
		if !bindingCanAttach(&managed, asset, source) {
			return ErrPAMInput
		}
		var current model.PAMAssetAccountBinding
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("asset_id = ? AND account_id = ?", asset.Id, id).First(&current).Error; err != nil {
			return err
		}
		if current.Revision != input.Revision {
			return ErrPAMRevision
		}
		updated = repository.NewPAMBinding(asset, &managed, operator.Uid)
		if repository.BindingMatchesAsset(&current, asset) {
			updated.PasswordConfig = current.PasswordConfig
		}
		updated.ID, updated.CreatorID, updated.CreatedAt = current.ID, current.CreatorID, current.CreatedAt
		updated.Revision, updated.Enabled = current.Revision+1, input.Enabled
		if err := tx.Select("target_host", "gateway_id", "protocols", "password_config", "enabled", "revision", "updater_id", "updated_at").Save(updated).Error; err != nil {
			return err
		}
		history := NewHistoryService().CreateHistoryRecord(ctx, model.ACTION_UPDATE, &managed, &managed, operator.Uid)
		history.Old["binding"], history.New["binding"] = current, updated
		return tx.Create(history).Error
	})
	return updated, err
}
