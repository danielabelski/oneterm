package service

import (
	"context"
	"errors"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	"github.com/veops/oneterm/pkg/secret"
)

var ErrCredentialInput = errors.New("provide a complete credential when replacing its value or authentication type")

var CredentialStorageFields = []string{"password", "pk", "phrase", "credential_version_id", "credential_revision"}

func credentialMaterial(owner model.CredentialOwner) (secret.Material, error) {
	password, key, phrase := owner.CredentialValues()
	if len(password)+len(key)+len(phrase) > secret.MaxMaterialSize {
		return secret.Material{}, ErrCredentialInput
	}
	switch owner.CredentialAuthType() {
	case model.AUTHMETHOD_PASSWORD:
		if key != "" || phrase != "" {
			return secret.Material{}, ErrCredentialInput
		}
		return secret.NewPassword(password), nil
	case model.AUTHMETHOD_PUBLICKEY:
		if password != "" || key == "" {
			return secret.Material{}, ErrCredentialInput
		}
		var err error
		if phrase == "" {
			_, err = ssh.ParsePrivateKey([]byte(key))
		} else {
			_, err = ssh.ParsePrivateKeyWithPassphrase([]byte(key), []byte(phrase))
		}
		if err != nil {
			return secret.Material{}, ErrCredentialInput
		}
		return secret.NewSSHKey(key, phrase), nil
	default:
		return secret.Material{}, ErrCredentialInput
	}
}

func ValidateStoredCredential(owner model.CredentialOwner) error {
	material, err := credentialMaterial(owner)
	if err != nil {
		return err
	}
	if _, err := material.EncodeForEncryption(); err != nil {
		return ErrCredentialInput
	}
	return nil
}

func persistCredential(ctx context.Context, tx *gorm.DB, owner model.CredentialOwner, uid int, previous string) error {
	material, err := credentialMaterial(owner)
	if err != nil {
		return err
	}
	repo, err := repository.ConfiguredCredentials()
	if err != nil {
		return err
	}
	version, err := repo.Stage(ctx, tx, owner.CredentialOwnerKind(), owner.GetId(), uid, "", material)
	if err != nil {
		return err
	}
	if err := repo.Publish(ctx, tx, owner, previous, version.ID); err != nil {
		return err
	}
	owner.SetCredentialReference(version.ID)
	owner.SetCredentialValues("", "", "")
	return nil
}

func CreateStoredCredential(ctx context.Context, tx *gorm.DB, owner model.CredentialOwner, uid int) error {
	return persistCredential(ctx, tx, owner, uid, "")
}

// UpdateStoredCredential does not read or decrypt the old value for metadata edits.
func UpdateStoredCredential(ctx context.Context, tx *gorm.DB, owner model.CredentialOwner, uid int, fields map[string]any) error {
	var current model.CredentialOwner
	switch owner.CredentialOwnerKind() {
	case model.PAMOwnerAccount:
		current = &model.Account{}
	case model.PAMOwnerGateway:
		current = &model.Gateway{}
	default:
		return ErrCredentialInput
	}
	if err := tx.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).First(current, owner.GetId()).Error; err != nil {
		return err
	}
	if account, ok := current.(*model.Account); ok && account.Managed {
		if name, changed := fields["account"]; changed && name != account.Account {
			return ErrCredentialInput
		}
		if _, changed := fields["account_type"]; changed && owner.CredentialAuthType() != account.AccountType {
			return ErrCredentialInput
		}
	}
	if _, present := fields["account_type"]; !present {
		owner.SetCredentialAuthType(current.CredentialAuthType())
	}
	changed := false
	for _, field := range []string{"password", "pk", "phrase"} {
		if value, present := fields[field]; present {
			if _, valid := value.(string); !valid {
				return ErrCredentialInput
			}
			changed = true
		}
	}
	if !changed {
		if owner.CredentialAuthType() != current.CredentialAuthType() {
			return ErrCredentialInput
		}
		owner.SetCredentialReference(current.CredentialReference())
		owner.SetCredentialValues("", "", "")
		return nil
	}
	required := "password"
	if owner.CredentialAuthType() == model.AUTHMETHOD_PUBLICKEY {
		required = "pk"
	}
	if _, present := fields[required]; !present {
		return ErrCredentialInput
	}
	if account, ok := current.(*model.Account); ok && account.Managed {
		var active int64
		if err := tx.Model(&model.PAMExecution{}).Where("active_account_id = ?", account.Id).Count(&active).Error; err != nil {
			return err
		}
		if active != 0 {
			return ErrCredentialInput
		}
	}
	return persistCredential(ctx, tx, owner, uid, current.CredentialReference())
}
