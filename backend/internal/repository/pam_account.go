package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/pkg/db"
	apiErrors "github.com/veops/oneterm/pkg/errors"
)

var (
	ErrPAMBindingUnavailable = &apiErrors.ApiError{Code: apiErrors.ErrPAMBindingUnavailable}
	ErrPAMBindingChanged     = &apiErrors.ApiError{Code: apiErrors.ErrPAMBindingChanged}
)

type PAMAccountRepository struct{ database *gorm.DB }

func NewPAMAccountRepository() *PAMAccountRepository {
	return &PAMAccountRepository{database: db.GetDB()}
}

func (r *PAMAccountRepository) Transaction(ctx context.Context, fn func(*gorm.DB) error) error {
	return r.database.WithContext(ctx).Transaction(fn)
}

func (r *PAMAccountRepository) Query(ctx context.Context) *gorm.DB {
	return r.database.WithContext(ctx).Model(&model.Account{}).Where("managed = ?", true)
}

func (r *PAMAccountRepository) Get(ctx context.Context, id int) (*model.Account, error) {
	var account model.Account
	err := r.database.WithContext(ctx).Where("managed = ?", true).First(&account, id).Error
	return &account, err
}

func (r *PAMAccountRepository) Bindings(ctx context.Context, id int) *gorm.DB {
	return r.database.WithContext(ctx).Model(&model.PAMAssetAccountBinding{}).Where("account_id = ?", id)
}

func CredentialOwnerAvailable(ctx context.Context, tx *gorm.DB, owner model.CredentialOwner) (bool, error) {
	managed, ok := owner.(*model.Account)
	if !ok || !managed.Managed {
		return true, nil
	}
	if !managed.Enabled {
		return false, nil
	}
	if managed.AuthorityKind == model.PAMAuthorityAsset {
		var count int64
		err := tx.WithContext(ctx).Model(&model.Asset{}).Where("id = ?", managed.AuthorityAssetID).Count(&count).Error
		return count == 1, err
	}
	return managed.AuthorityKind == model.PAMAuthorityShared, nil
}

func PAMNativeKey(authorityKind, authorityRef, username, qualifier string) string {
	data, _ := json.Marshal([]string{authorityKind, authorityRef, username, qualifier})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func normalizedHost(host string) string {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap().String()
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func bindingProtocols(protocols []string) model.Slice[string] {
	result := append(model.Slice[string]{}, protocols...)
	sort.Strings(result)
	return result
}

func NewPAMBinding(asset *model.Asset, account *model.Account, uid int) *model.PAMAssetAccountBinding {
	return &model.PAMAssetAccountBinding{AssetID: asset.Id, AccountID: account.Id, AuthorityKind: account.AuthorityKind, AuthorityRef: account.AuthorityRef, TargetHost: normalizedHost(asset.Ip),
		GatewayID: asset.GatewayId, Protocols: bindingProtocols(asset.Protocols), Enabled: true, Revision: 1,
		CreatorID: uid, UpdaterID: uid}
}

func BindingMatchesAsset(binding *model.PAMAssetAccountBinding, asset *model.Asset) bool {
	if binding.AssetID != asset.Id || binding.TargetHost != normalizedHost(asset.Ip) || binding.GatewayID != asset.GatewayId {
		return false
	}
	protocols := bindingProtocols(asset.Protocols)
	if len(protocols) != len(binding.Protocols) {
		return false
	}
	for i, protocol := range protocols {
		if binding.Protocols[i] != protocol {
			return false
		}
	}
	return true
}

func LoadPAMAdoptionSource(ctx context.Context, tx *gorm.DB, assetID, accountID int) (*model.Asset, *model.Account, error) {
	if assetID <= 0 || accountID <= 0 {
		return nil, nil, ErrCredentialState
	}
	asset, account := &model.Asset{}, &model.Account{}
	if err := tx.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).First(asset, assetID).Error; err != nil {
		return nil, nil, err
	}
	if err := tx.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).First(account, accountID).Error; err != nil {
		return nil, nil, err
	}
	return asset, account, nil
}

// EffectivePAMAccount maps the existing connection IDs; absence alone selects the legacy path.
func EffectivePAMAccount(ctx context.Context, asset *model.Asset, source *model.Account) (*model.Account, error) {
	var binding model.PAMAssetAccountBinding
	err := db.GetDB().WithContext(ctx).Where("asset_id = ? AND account_id = ?", asset.Id, source.Id).First(&binding).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !binding.Enabled || binding.AccountID <= 0 {
		return nil, ErrPAMBindingUnavailable
	}
	if !BindingMatchesAsset(&binding, asset) {
		return nil, ErrPAMBindingChanged
	}
	var managed model.Account
	if err := db.GetDB().WithContext(ctx).Where("managed = ?", true).First(&managed, binding.AccountID).Error; err != nil {
		return nil, ErrPAMBindingUnavailable
	}
	if !managed.Enabled || (managed.AuthorityKind == model.PAMAuthorityAsset && managed.AuthorityAssetID != asset.Id) {
		return nil, ErrPAMBindingUnavailable
	}
	return &managed, nil
}
