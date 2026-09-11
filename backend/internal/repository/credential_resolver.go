package repository

import (
	"context"

	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/pkg/config"
	"github.com/veops/oneterm/pkg/db"
)

func ConfiguredCredentials() (*PAMCredentialRepository, error) {
	return NewPAMCredentialRepository(db.GetDB(), []byte(config.Cfg.Auth.Aes.Key))
}

// ResolveCredential is a private, post-authorization adapter for existing protocol drivers.
func ResolveCredential(ctx context.Context, owner model.CredentialOwner) error {
	repo, err := ConfiguredCredentials()
	if err != nil {
		return err
	}
	material, err := repo.Resolve(ctx, owner, []byte(config.Cfg.Auth.Aes.Iv))
	if err != nil {
		return err
	}
	owner.SetCredentialValues(material.PasswordValue(), material.PrivateKeyValue(), material.PassphraseValue())
	return nil
}

// ResolveAssetAccountCredential only changes explicitly bound accounts after normal V2 authorization.
func ResolveAssetAccountCredential(ctx context.Context, asset *model.Asset, source *model.Account) error {
	managed, err := EffectivePAMAccount(ctx, asset, source)
	if err != nil {
		return err
	}
	if managed == nil {
		if source.Managed {
			source.SetCredentialValues("", "", "")
			return ErrPAMBindingUnavailable
		}
		return ResolveCredential(ctx, source)
	}
	if err := ResolveCredential(ctx, managed); err != nil {
		return err
	}
	source.Account, source.AccountType = managed.Account, managed.AccountType
	password, key, phrase := managed.CredentialValues()
	source.SetCredentialValues(password, key, phrase)
	return nil
}
