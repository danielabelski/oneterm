package service

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/veops/oneterm/internal/model"
)

var ErrPAMCredentialShared = errors.New("the account is also associated with other assets")

// Password ownership follows explicit asset/account associations, not access grants.
// Selector rules may include every future account without assigning their credentials to an asset.
func validatePAMAccountScope(ctx context.Context, tx *gorm.DB, account *model.Account, assetID int) error {
	var count int64
	if err := tx.WithContext(ctx).Model(&model.PAMAssetAccountBinding{}).
		Where("account_id = ? AND asset_id <> ?", account.Id, assetID).Count(&count).Error; err != nil {
		return err
	}
	if count != 0 {
		return ErrPAMCredentialShared
	}
	var assets []model.Asset
	if err := tx.WithContext(ctx).Select("id", "authorization").Where("id <> ?", assetID).Find(&assets).Error; err != nil {
		return err
	}
	for _, asset := range assets {
		if _, used := asset.Authorization[account.Id]; used {
			return ErrPAMCredentialShared
		}
	}
	return nil
}
