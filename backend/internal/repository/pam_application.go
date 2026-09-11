package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/pkg/db"
)

type PAMApplicationRepository struct{ database *gorm.DB }

func NewPAMApplicationRepository() *PAMApplicationRepository {
	return &PAMApplicationRepository{database: db.GetDB()}
}

func (r *PAMApplicationRepository) Get(ctx context.Context, id int) (*model.PAMApplication, error) {
	var application model.PAMApplication
	err := r.database.WithContext(ctx).First(&application, id).Error
	return &application, err
}

func (r *PAMApplicationRepository) Transaction(ctx context.Context, fn func(*gorm.DB) error) error {
	return r.database.WithContext(ctx).Transaction(fn)
}

func (r *PAMApplicationRepository) Query(ctx context.Context) *gorm.DB {
	return r.database.WithContext(ctx).Model(&model.PAMApplication{})
}

func (r *PAMApplicationRepository) TargetQuery(ctx context.Context, kind string) (*gorm.DB, error) {
	owner, err := CredentialOwnerModel(kind)
	if err != nil {
		return nil, err
	}
	return r.database.WithContext(ctx).Model(owner).Select("id", "name", "account"), nil
}

type PAMTargetResource struct {
	ID         int `gorm:"column:id"`
	ResourceID int `gorm:"column:resource_id"`
}

func (r *PAMApplicationRepository) TargetResources(ctx context.Context, kind string, ids []int) ([]PAMTargetResource, error) {
	owner, err := CredentialOwnerModel(kind)
	if err != nil {
		return nil, err
	}
	var resources []PAMTargetResource
	err = r.database.WithContext(ctx).Model(owner).Select("id", "resource_id").Where("id IN ?", ids).Find(&resources).Error
	return resources, err
}

func (r *PAMApplicationRepository) BeginAudit(ctx context.Context, audit *model.PAMAccessAudit) error {
	return r.database.WithContext(ctx).Create(audit).Error
}

func (r *PAMApplicationRepository) FinishAudit(ctx context.Context, audit *model.PAMAccessAudit) error {
	result := r.database.WithContext(ctx).Model(&model.PAMAccessAudit{}).
		Where("id = ? AND outcome = ?", audit.Id, "pending").Updates(map[string]any{
		"outcome": audit.Outcome, "reason_code": audit.ReasonCode, "version_id": audit.VersionID,
		"finished_at": time.Now(), "grant_id": audit.GrantID,
	})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return errors.New("credential audit state changed")
	}
	return nil
}

// WithApplication serializes short credential admission against grant changes and revocation.
func (r *PAMApplicationRepository) WithApplication(ctx context.Context, id int, fn func(*gorm.DB, *model.PAMApplication) error) error {
	return r.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var application model.PAMApplication
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&application, id).Error; err != nil {
			return err
		}
		return fn(tx, &application)
	})
}

func CredentialOwnerModel(kind string) (model.CredentialOwner, error) {
	switch kind {
	case model.PAMOwnerAccount:
		return &model.Account{}, nil
	case model.PAMOwnerGateway:
		return &model.Gateway{}, nil
	default:
		return nil, ErrCredentialState
	}
}

func LoadCredentialOwner(ctx context.Context, tx *gorm.DB, target model.PAMCredentialTarget) (model.CredentialOwner, error) {
	owner, err := CredentialOwnerModel(target.Kind)
	if err != nil || target.ID <= 0 {
		return nil, ErrCredentialState
	}
	if err := tx.WithContext(ctx).First(owner, target.ID).Error; err != nil {
		return nil, err
	}
	return owner, nil
}
