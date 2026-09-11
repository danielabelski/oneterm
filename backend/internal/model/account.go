package model

import (
	"time"

	"gorm.io/plugin/soft_delete"
)

const (
	PAMAuthorityAsset  = "asset_local"
	PAMAuthorityShared = "shared"
)

type Account struct {
	Id                  int    `json:"id" gorm:"column:id;primarykey;autoIncrement"`
	Name                string `json:"name" gorm:"column:name;uniqueIndex:name_del;size:128"`
	AccountType         int    `json:"account_type,omitempty" gorm:"column:account_type"`
	Account             string `json:"account" gorm:"column:account"`
	Password            string `json:"password,omitempty" gorm:"column:password"`
	Pk                  string `json:"pk,omitempty" gorm:"column:pk"`
	Phrase              string `json:"phrase,omitempty" gorm:"column:phrase"`
	CredentialVersionID string `json:"-" gorm:"size:64;not null;default:''"`
	CredentialRevision  uint64 `json:"credential_revision" gorm:"not null;default:0"`
	Managed             bool   `json:"managed" gorm:"not null;default:false"`
	AuthorityKind       string `json:"authority_kind,omitempty" gorm:"size:24"`
	AuthorityRef        string `json:"authority_ref,omitempty" gorm:"size:128"`
	AuthorityAssetID    int    `json:"authority_asset_id,omitempty" gorm:"not null;default:0;index"`
	NativeQualifier     string `json:"native_qualifier,omitempty" gorm:"size:255"`
	NativeKey           string `json:"-" gorm:"size:64;default:null;uniqueIndex"`
	Platform            string `json:"platform,omitempty" gorm:"size:32"`
	Enabled             bool   `json:"enabled" gorm:"not null;default:true"`
	Revision            uint64 `json:"revision" gorm:"not null;default:1"`

	Permissions []string              `json:"permissions,omitempty" gorm:"-"`
	ResourceId  int                   `json:"resource_id,omitempty" gorm:"column:resource_id"`
	CreatorId   int                   `json:"creator_id,omitempty" gorm:"column:creator_id"`
	UpdaterId   int                   `json:"updater_id,omitempty" gorm:"column:updater_id"`
	CreatedAt   time.Time             `json:"created_at,omitempty" gorm:"column:created_at"`
	UpdatedAt   time.Time             `json:"updated_at,omitempty" gorm:"column:updated_at"`
	DeletedAt   soft_delete.DeletedAt `json:"-" gorm:"column:deleted_at;uniqueIndex:name_del"`

	AssetCount int64 `json:"asset_count,omitempty" gorm:"-"`
}

func (m *Account) TableName() string {
	return "account"
}

func (m *Account) CredentialOwnerKind() string                { return PAMOwnerAccount }
func (m *Account) UsesLegacyCredentialStorage() bool          { return true }
func (m *Account) CredentialAuthType() int                    { return m.AccountType }
func (m *Account) CredentialReference() string                { return m.CredentialVersionID }
func (m *Account) CredentialValues() (string, string, string) { return m.Password, m.Pk, m.Phrase }
func (m *Account) SetCredentialValues(password, privateKey, passphrase string) {
	m.Password, m.Pk, m.Phrase = password, privateKey, passphrase
}
func (m *Account) SetCredentialReference(version string) { m.CredentialVersionID = version }
func (m *Account) SetId(id int) {
	m.Id = id
}
func (m *Account) SetCreatorId(creatorId int) {
	m.CreatorId = creatorId
}
func (m *Account) SetUpdaterId(updaterId int) {
	m.UpdaterId = updaterId
}
func (m *Account) SetResourceId(resourceId int) {
	m.ResourceId = resourceId
}
func (m *Account) GetResourceId() int {
	return m.ResourceId
}
func (m *Account) GetName() string {
	return m.Name
}
func (m *Account) GetId() int {
	return m.Id
}

func (m *Account) SetPerms(perms []string) {
	m.Permissions = perms
}

func (m *Account) SetCredentialAuthType(kind int) { m.AccountType = kind }

type AccountCount struct {
	Id    int   `json:"id" gorm:"id"`
	Count int64 `json:"count" gorm:"count"`
}
