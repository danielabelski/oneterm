package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	"github.com/veops/oneterm/pkg/db"
	apiErrors "github.com/veops/oneterm/pkg/errors"
)

const PAMSessionLeaseTTL = 45 * time.Second

func AdmitPAMConnection(ctx context.Context, sessionID string, permit *model.PAMConnectionPermit) error {
	if permit == nil {
		return nil
	}
	if sessionID == "" || len(sessionID) > 128 || strings.TrimSpace(sessionID) != sessionID || permit.LeaseID != "" {
		return ErrPAMInput
	}
	if strings.ContainsAny(sessionID, "/\\\x00\r\n") {
		return ErrPAMInput
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	subject, err := acl.GetPAMKeySubject(ctx, permit.UID)
	if err != nil || subject.Blocked {
		return ErrPAMDenied
	}
	var admitted model.PAMSessionLease
	err = db.GetDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		target := model.PAMCredentialTarget{Kind: model.PAMOwnerAccount, ID: permit.OwnerID}
		return repository.WithPAMPolicy(tx, target, "UPDATE", func(tx *gorm.DB, owner model.CredentialOwner, policy *model.PAMPolicy) error {
			if err := checkPAMConnectionScope(ctx, tx, permit, owner, policy); err != nil {
				return err
			}
			now := time.Now()
			var previous model.PAMSessionLease
			err := tx.Where("session_id = ?", sessionID).First(&previous).Error
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			if err == nil {
				return &apiErrors.ApiError{Code: apiErrors.ErrPAMSessionConflict}
			}
			var recorded int64
			if err := tx.Model(&model.Session{}).Where("session_id = ?", sessionID).Count(&recorded).Error; err != nil {
				return err
			}
			if recorded != 0 {
				return &apiErrors.ApiError{Code: apiErrors.ErrPAMSessionConflict}
			}
			if policy.MaxSessions > 0 {
				var count int64
				if err := tx.Model(&model.PAMSessionLease{}).Where("owner_id = ? AND state = ? AND lease_expires_at > ?",
					permit.OwnerID, "active", now).Where("deadline IS NULL OR deadline > ?", now).Count(&count).Error; err != nil {
					return err
				}
				if count >= int64(policy.MaxSessions) {
					return &apiErrors.ApiError{Code: apiErrors.ErrPAMSessionCapacity}
				}
			}
			deadline := permit.Deadline
			if policy.MaxSessionMinutes > 0 {
				limit := now.Add(time.Duration(policy.MaxSessionMinutes) * time.Minute)
				if deadline == nil || limit.Before(*deadline) {
					deadline = &limit
				}
			}
			admitted = model.PAMSessionLease{SessionID: sessionID, ID: uuid.NewString(), OwnerID: permit.OwnerID, UID: permit.UID,
				AssetID: permit.AssetID, AccountID: permit.AccountID, State: "active", LeaseExpiresAt: now.Add(PAMSessionLeaseTTL), Deadline: deadline}
			return tx.Create(&admitted).Error
		})
	})
	if err != nil {
		if translator, ok := db.GetDB().Dialector.(gorm.ErrorTranslator); ok {
			if errors.Is(translator.Translate(err), gorm.ErrDuplicatedKey) {
				return &apiErrors.ApiError{Code: apiErrors.ErrPAMSessionConflict}
			}
		}
		return err
	}
	permit.LeaseID, permit.LeaseExpiresAt, permit.Deadline = admitted.ID, admitted.LeaseExpiresAt, admitted.Deadline
	return nil
}

func checkPAMSessionLease(tx *gorm.DB, permit *model.PAMConnectionPermit) error {
	if permit.LeaseID == "" {
		return nil
	}
	var lease model.PAMSessionLease
	if err := tx.Where("id = ? AND owner_id = ? AND uid = ? AND asset_id = ? AND account_id = ?",
		permit.LeaseID, permit.OwnerID, permit.UID, permit.AssetID, permit.AccountID).First(&lease).Error; err != nil {
		return ErrPAMDenied
	}
	now := time.Now()
	if lease.State != "active" || !now.Before(lease.LeaseExpiresAt) || (lease.Deadline != nil && !now.Before(*lease.Deadline)) {
		return ErrPAMDenied
	}
	return nil
}

func renewPAMSessionLease(ctx context.Context, permit *model.PAMConnectionPermit) (time.Time, error) {
	if permit.LeaseID == "" {
		return time.Time{}, nil
	}
	now := time.Now()
	expires := now.Add(PAMSessionLeaseTTL)
	result := db.GetDB().WithContext(ctx).Model(&model.PAMSessionLease{}).
		Where("id = ? AND owner_id = ? AND uid = ? AND state = ? AND lease_expires_at > ?", permit.LeaseID, permit.OwnerID, permit.UID, "active", now).
		Where("deadline IS NULL OR deadline > ?", now).Update("lease_expires_at", expires)
	if result.Error != nil {
		return time.Time{}, result.Error
	}
	if result.RowsAffected != 1 {
		// MySQL may report zero changed rows for two heartbeats in the same timestamp precision.
		var current model.PAMSessionLease
		err := db.GetDB().WithContext(ctx).Select("lease_expires_at").
			Where("id = ? AND owner_id = ? AND uid = ? AND state = ? AND lease_expires_at > ?", permit.LeaseID, permit.OwnerID, permit.UID, "active", time.Now()).
			Where("deadline IS NULL OR deadline > ?", time.Now()).First(&current).Error
		if err != nil {
			return time.Time{}, ErrPAMDenied
		}
		return current.LeaseExpiresAt, nil
	}
	return expires, nil
}

func ReleasePAMConnection(ctx context.Context, permit *model.PAMConnectionPermit) error {
	if permit == nil || permit.LeaseID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return db.GetDB().WithContext(ctx).Model(&model.PAMSessionLease{}).
		Where("id = ? AND owner_id = ? AND uid = ? AND state = ?", permit.LeaseID, permit.OwnerID, permit.UID, "active").
		Updates(map[string]any{"state": "closed", "lease_expires_at": time.Now()}).Error
}

func ActivatePAMConnection(ctx context.Context, permit *model.PAMConnectionPermit) error {
	if permit == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := CheckPAMConnectionPermit(ctx, permit); err != nil {
		return err
	}
	expires, err := renewPAMSessionLease(ctx, permit)
	if err == nil {
		permit.LeaseExpiresAt = expires
	}
	return err
}
