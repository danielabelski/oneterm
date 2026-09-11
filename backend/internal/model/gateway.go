package model

import (
	"time"

	"gorm.io/plugin/soft_delete"
)

type Gateway struct {
	Id                  int    `json:"id" gorm:"column:id;primarykey;autoIncrement"`
	Name                string `json:"name" gorm:"column:name;uniqueIndex:name_del;size:128"`
	Host                string `json:"host" gorm:"column:host"`
	Port                int    `json:"port" gorm:"column:port"`
	AccountType         int    `json:"account_type" gorm:"column:account_type"`
	Account             string `json:"account" gorm:"column:account"`
	Password            string `json:"password" gorm:"column:password"`
	Pk                  string `json:"pk" gorm:"column:pk"`
	Phrase              string `json:"phrase" gorm:"column:phrase"`
	CredentialVersionID string `json:"-" gorm:"size:64;not null;default:''"`
	CredentialRevision  uint64 `json:"-" gorm:"not null;default:0"`

	Permissions []string              `json:"permissions" gorm:"-"`
	ResourceId  int                   `json:"resource_id" gorm:"column:resource_id"`
	CreatorId   int                   `json:"creator_id" gorm:"column:creator_id"`
	UpdaterId   int                   `json:"updater_id" gorm:"column:updater_id"`
	CreatedAt   time.Time             `json:"created_at" gorm:"column:created_at"`
	UpdatedAt   time.Time             `json:"updated_at" gorm:"column:updated_at"`
	DeletedAt   soft_delete.DeletedAt `json:"-" gorm:"column:deleted_at;uniqueIndex:name_del"`

	AssetCount int64 `json:"asset_count" gorm:"-"`
}

func (m *Gateway) TableName() string {
	return "gateway"
}

func (m *Gateway) CredentialOwnerKind() string                { return PAMOwnerGateway }
func (m *Gateway) UsesLegacyCredentialStorage() bool          { return true }
func (m *Gateway) CredentialAuthType() int                    { return m.AccountType }
func (m *Gateway) CredentialReference() string                { return m.CredentialVersionID }
func (m *Gateway) CredentialValues() (string, string, string) { return m.Password, m.Pk, m.Phrase }
func (m *Gateway) SetCredentialValues(password, privateKey, passphrase string) {
	m.Password, m.Pk, m.Phrase = password, privateKey, passphrase
}
func (m *Gateway) SetCredentialReference(version string) { m.CredentialVersionID = version }
func (m *Gateway) SetId(id int) {
	m.Id = id
}
func (m *Gateway) SetCreatorId(creatorId int) {
	m.CreatorId = creatorId
}
func (m *Gateway) SetUpdaterId(updaterId int) {
	m.UpdaterId = updaterId
}
func (m *Gateway) SetResourceId(resourceId int) {
	m.ResourceId = resourceId
}
func (m *Gateway) GetResourceId() int {
	return m.ResourceId
}
func (m *Gateway) GetName() string {
	return m.Name
}
func (m *Gateway) GetId() int {
	return m.Id
}

func (m *Gateway) SetPerms(perms []string) {
	m.Permissions = perms
}

func (m *Gateway) SetCredentialAuthType(kind int) { m.AccountType = kind }

type GatewayCount struct {
	Id    int   `gorm:"column:id"`
	Count int64 `gorm:"column:count"`
}
