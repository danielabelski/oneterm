package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/pkg/secret"
)

var ErrCredentialState = errors.New("credential version is not available for this operation")

type PAMCredentialRepository struct {
	db        *gorm.DB
	wrapping  *secret.Codec
	legacyKey []byte
}

func NewPAMCredentialRepository(db *gorm.DB, masterKey []byte) (*PAMCredentialRepository, error) {
	if db == nil || (len(masterKey) != 16 && len(masterKey) != 24 && len(masterKey) != 32) {
		return nil, secret.ErrKey
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, masterKey, nil, []byte("oneterm/pam/wrapping/v1")), key); err != nil {
		return nil, err
	}
	wrapping, err := secret.New("configured-kek-v1", map[string][]byte{"configured-kek-v1": key})
	if err != nil {
		return nil, err
	}
	return &PAMCredentialRepository{db: db, wrapping: wrapping, legacyKey: append([]byte(nil), masterKey...)}, nil
}

func (r *PAMCredentialRepository) EnsureDataKey(ctx context.Context) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.SystemConfig{Key: model.SysConfigPAMDataKey}).Error; err != nil {
			return err
		}
		var config model.SystemConfig
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("config_key = ?", model.SysConfigPAMDataKey).First(&config).Error; err != nil {
			return err
		}
		if config.Value != "" {
			_, err := r.codec(ctx, tx, config.Value)
			return err
		}
		var active []model.PAMDataKey
		if err := tx.Where("state = ?", model.PAMVersionActive).Order("id").Limit(2).Find(&active).Error; err != nil {
			return err
		}
		if len(active) > 1 {
			return secret.ErrKey
		}
		if len(active) == 1 {
			if _, err := r.codec(ctx, tx, active[0].ID); err != nil {
				return err
			}
			return tx.Model(&config).Update("value", active[0].ID).Error
		}
		var count int64
		if err := tx.Model(&model.PAMCredentialVersion{}).Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return secret.ErrKey
		}
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return err
		}
		id := uuid.NewString()
		wrapped, err := r.wrapping.Seal("data-key/"+id, key)
		if err != nil {
			return err
		}
		if err := tx.Create(&model.PAMDataKey{ID: id, WrappedKey: wrapped, State: model.PAMVersionActive}).Error; err != nil {
			return err
		}
		return tx.Model(&config).Update("value", id).Error
	})
}

func (r *PAMCredentialRepository) codec(ctx context.Context, tx *gorm.DB, id string) (*secret.Codec, error) {
	var key model.PAMDataKey
	if err := tx.WithContext(ctx).Where("id = ?", id).First(&key).Error; err != nil {
		return nil, secret.ErrKey
	}
	if key.State != model.PAMVersionActive && key.State != model.PAMVersionRetained {
		return nil, secret.ErrKey
	}
	plain, err := r.wrapping.Open("data-key/"+id, key.WrappedKey)
	if err != nil {
		return nil, err
	}
	return secret.New(id, map[string][]byte{id: plain})
}

func credentialContext(owner string, id int, version string) string {
	return fmt.Sprintf("%s/%d/version/%s", owner, id, version)
}

// Stage participates in the caller's transaction; it does not publish an active reference.
func (r *PAMCredentialRepository) Stage(ctx context.Context, tx *gorm.DB, owner string, id, creator int, operation string, material secret.Material) (*model.PAMCredentialVersion, error) {
	if tx == nil || id <= 0 || (owner != model.PAMOwnerAccount && owner != model.PAMOwnerGateway) {
		return nil, ErrCredentialState
	}
	var config model.SystemConfig
	if err := tx.WithContext(ctx).Where("config_key = ?", model.SysConfigPAMDataKey).First(&config).Error; err != nil {
		return nil, err
	}
	codec, err := r.codec(ctx, tx, config.Value)
	if err != nil {
		return nil, err
	}
	version := &model.PAMCredentialVersion{
		ID: uuid.NewString(), OwnerKind: owner, OwnerID: id, Kind: material.Kind(), KeyID: config.Value,
		State: model.PAMVersionPending, CreatorID: creator, OperationID: operation,
	}
	plain, err := material.EncodeForEncryption()
	if err != nil {
		return nil, err
	}
	version.Ciphertext, err = codec.Seal(credentialContext(owner, id, version.ID), plain)
	if err != nil {
		return nil, err
	}
	if err = tx.WithContext(ctx).Create(version).Error; err != nil {
		return nil, err
	}
	return version, nil
}

func (r *PAMCredentialRepository) ReadActive(ctx context.Context, owner string, id int, version string) (secret.Material, error) {
	return r.read(ctx, r.db, owner, id, version, model.PAMVersionActive)
}

func (r *PAMCredentialRepository) ReadCandidate(ctx context.Context, tx *gorm.DB, owner string, id int, version string) (secret.Material, error) {
	return r.read(ctx, tx, owner, id, version, model.PAMVersionPending)
}

func (r *PAMCredentialRepository) read(ctx context.Context, tx *gorm.DB, owner string, id int, version, state string) (secret.Material, error) {
	if tx == nil || id <= 0 || version == "" {
		return secret.Material{}, ErrCredentialState
	}
	var data model.PAMCredentialVersion
	err := tx.WithContext(ctx).Where("id = ? AND owner_kind = ? AND owner_id = ? AND state = ?", version, owner, id, state).First(&data).Error
	if err != nil {
		return secret.Material{}, ErrCredentialState
	}
	codec, err := r.codec(ctx, tx, data.KeyID)
	if err != nil {
		return secret.Material{}, err
	}
	plain, err := codec.Open(credentialContext(owner, id, version), data.Ciphertext)
	if err != nil {
		return secret.Material{}, err
	}
	material, err := secret.DecodeMaterial(plain)
	if err != nil || material.Kind() != data.Kind {
		return secret.Material{}, secret.ErrMaterial
	}
	return material, nil
}

// Activate must share the transaction that compare-and-swaps the owner's current version.
func (r *PAMCredentialRepository) Activate(ctx context.Context, tx *gorm.DB, owner string, id int, previous, candidate string) error {
	if tx == nil || candidate == "" || previous == candidate || id <= 0 {
		return ErrCredentialState
	}
	result := tx.WithContext(ctx).Model(&model.PAMCredentialVersion{}).
		Where("id = ? AND owner_kind = ? AND owner_id = ? AND state = ?", candidate, owner, id, model.PAMVersionPending).
		Update("state", model.PAMVersionActive)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrCredentialState
	}
	if previous != "" {
		result = tx.WithContext(ctx).Model(&model.PAMCredentialVersion{}).
			Where("id = ? AND owner_kind = ? AND owner_id = ? AND state = ?", previous, owner, id, model.PAMVersionActive).
			Update("state", model.PAMVersionRetained)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrCredentialState
		}
	}
	return nil
}

// Publish updates the owning record and the version states inside the caller's transaction.
func (r *PAMCredentialRepository) Publish(ctx context.Context, tx *gorm.DB, owner model.CredentialOwner, previous, candidate string) error {
	if tx == nil || owner == nil || owner.GetId() <= 0 {
		return ErrCredentialState
	}
	material, err := r.ReadCandidate(ctx, tx, owner.CredentialOwnerKind(), owner.GetId(), candidate)
	if err != nil || !credentialTypeMatches(owner.CredentialAuthType(), material.Kind()) {
		return ErrCredentialState
	}
	updates := map[string]any{"credential_version_id": candidate, "credential_revision": gorm.Expr("credential_revision + 1")}
	if owner.UsesLegacyCredentialStorage() {
		updates["password"], updates["pk"], updates["phrase"] = "", "", ""
	}
	result := tx.WithContext(ctx).Model(owner).
		Where("id = ? AND credential_version_id = ?", owner.GetId(), previous).
		Updates(updates)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrCredentialState
	}
	return r.Activate(ctx, tx, owner.CredentialOwnerKind(), owner.GetId(), previous, candidate)
}

func credentialTypeMatches(authType int, kind string) bool {
	return authType == model.AUTHMETHOD_PASSWORD && kind == secret.Password ||
		authType == model.AUTHMETHOD_PUBLICKEY && kind == secret.SSHPrivateKey
}

// Resolve supports unmigrated records without writing to storage during a read.
// The caller must authorize the operation before entering this private storage path.
func (r *PAMCredentialRepository) Resolve(ctx context.Context, owner model.CredentialOwner, legacyIV []byte) (secret.Material, error) {
	return r.ResolveInTransaction(ctx, r.db, owner, legacyIV)
}

func (r *PAMCredentialRepository) ResolveInTransaction(ctx context.Context, tx *gorm.DB, owner model.CredentialOwner, legacyIV []byte) (secret.Material, error) {
	if owner == nil || owner.GetId() <= 0 {
		return secret.Material{}, ErrCredentialState
	}
	if version := owner.CredentialReference(); version != "" {
		material, err := r.read(ctx, tx, owner.CredentialOwnerKind(), owner.GetId(), version, model.PAMVersionActive)
		if err != nil {
			return secret.Material{}, err
		}
		if !credentialTypeMatches(owner.CredentialAuthType(), material.Kind()) {
			return secret.Material{}, secret.ErrMaterial
		}
		return material, nil
	}
	if !owner.UsesLegacyCredentialStorage() {
		return secret.Material{}, ErrCredentialState
	}
	password, key, phrase := owner.CredentialValues()
	switch owner.CredentialAuthType() {
	case model.AUTHMETHOD_PASSWORD:
		plain, err := secret.OpenLegacyCBC(r.legacyKey, legacyIV, password)
		if err != nil {
			return secret.Material{}, err
		}
		return secret.NewPassword(string(plain)), nil
	case model.AUTHMETHOD_PUBLICKEY:
		plainKey, err := secret.OpenLegacyCBC(r.legacyKey, legacyIV, key)
		if err != nil {
			return secret.Material{}, err
		}
		plainPhrase, err := secret.OpenLegacyCBC(r.legacyKey, legacyIV, phrase)
		if err != nil {
			return secret.Material{}, err
		}
		return secret.NewSSHKey(string(plainKey), string(plainPhrase)), nil
	default:
		return secret.Material{}, secret.ErrMaterial
	}
}
