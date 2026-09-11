package model

import "time"

const (
	PAMOwnerAccount    = "account"
	PAMOwnerGateway    = "gateway"
	PAMVersionPending  = "pending"
	PAMVersionActive   = "active"
	PAMVersionRetained = "retained"
)

// CredentialOwner exposes storage fields to the credential broker, not to public DTOs.
type CredentialOwner interface {
	Model
	CredentialOwnerKind() string
	CredentialAuthType() int
	SetCredentialAuthType(int)
	CredentialReference() string
	CredentialValues() (password, privateKey, passphrase string)
	SetCredentialValues(password, privateKey, passphrase string)
	SetCredentialReference(version string)
	UsesLegacyCredentialStorage() bool
}

type PAMDataKey struct {
	ID         string    `gorm:"size:64;primaryKey" json:"id"`
	WrappedKey string    `gorm:"type:text;not null" json:"-"`
	State      string    `gorm:"size:16;not null;index" json:"state"`
	CreatedAt  time.Time `json:"created_at"`
}

func (PAMDataKey) TableName() string { return "pam_data_key" }

// PAMCredentialVersion is private storage, not a public CRUD resource.
type PAMCredentialVersion struct {
	ID          string    `gorm:"size:64;primaryKey" json:"id"`
	OwnerKind   string    `gorm:"size:16;not null;index:pam_credential_owner" json:"owner_kind"`
	OwnerID     int       `gorm:"not null;index:pam_credential_owner" json:"owner_id"`
	Kind        string    `gorm:"size:32;not null" json:"kind"`
	KeyID       string    `gorm:"size:64;not null;index" json:"key_id"`
	Ciphertext  string    `gorm:"size:4194304;not null" json:"-"`
	State       string    `gorm:"size:16;not null;index" json:"state"`
	OperationID string    `gorm:"size:64;index" json:"operation_id,omitempty"`
	CreatorID   int       `json:"creator_id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (PAMCredentialVersion) TableName() string { return "pam_credential_version" }

type PAMAssetAccountBinding struct {
	CurrentHost    string           `gorm:"-" json:"current_host"`
	RouteChanged   bool             `gorm:"-" json:"route_changed"`
	AssetName      string           `gorm:"-" json:"asset_name"`
	AccountName    string           `gorm:"-" json:"account_name"`
	ID             uint64           `gorm:"primaryKey" json:"id"`
	AssetID        int              `gorm:"not null;uniqueIndex:pam_asset_account" json:"asset_id"`
	AccountID      int              `gorm:"not null;uniqueIndex:pam_asset_account;index" json:"account_id"`
	TargetHost     string           `gorm:"size:512" json:"target_host"`
	GatewayID      int              `gorm:"not null;default:0" json:"gateway_id"`
	Protocols      Slice[string]    `gorm:"type:json" json:"protocols"`
	PasswordConfig Map[string, any] `gorm:"type:json" json:"password_config"`
	CreatorID      int              `json:"creator_id"`
	UpdaterID      int              `json:"updater_id"`
	AuthorityKind  string           `gorm:"size:24;not null;default:legacy_shared" json:"authority_kind"`
	AuthorityRef   string           `gorm:"size:128" json:"authority_ref,omitempty"`
	Revision       uint64           `gorm:"not null;default:1" json:"revision"`
	Enabled        bool             `gorm:"not null;default:true" json:"enabled"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
}

func (PAMAssetAccountBinding) TableName() string { return "pam_asset_account_binding" }
