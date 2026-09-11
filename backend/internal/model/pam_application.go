package model

import "time"

type PAMCredentialTarget struct {
	Kind string `json:"kind"`
	ID   int    `json:"id"`
}

// PAMApplication is an explicit grant to an ACL key identity, not a new user directory.
type PAMApplication struct {
	Id          int                     `json:"id" gorm:"primaryKey"`
	Name        string                  `json:"name" gorm:"size:128;not null;uniqueIndex"`
	ACLUID      int                     `json:"acl_uid" gorm:"not null;uniqueIndex"`
	Purpose     string                  `json:"purpose" gorm:"size:1024;not null"`
	Enabled     bool                    `json:"enabled" gorm:"not null;default:false"`
	Actions     Slice[string]           `json:"actions" gorm:"type:json;not null"`
	Targets     Map[string, Slice[int]] `json:"targets" gorm:"type:json;not null"`
	SourceCIDRs Slice[string]           `json:"source_cidrs" gorm:"type:json;not null"`
	ExpiresAt   *time.Time              `json:"expires_at"`
	Revision    uint64                  `json:"revision" gorm:"not null;default:1"`
	ResourceId  int                     `json:"resource_id" gorm:"not null"`
	Permissions []string                `json:"permissions,omitempty" gorm:"-"`
	CreatorId   int                     `json:"creator_id"`
	UpdaterId   int                     `json:"updater_id"`
	CreatedAt   time.Time               `json:"created_at"`
	UpdatedAt   time.Time               `json:"updated_at"`
}

func (PAMApplication) TableName() string          { return "pam_application" }
func (a *PAMApplication) GetId() int              { return a.Id }
func (a *PAMApplication) SetId(id int)            { a.Id = id }
func (a *PAMApplication) GetName() string         { return a.Name }
func (a *PAMApplication) GetResourceId() int      { return a.ResourceId }
func (a *PAMApplication) SetResourceId(id int)    { a.ResourceId = id }
func (a *PAMApplication) SetCreatorId(id int)     { a.CreatorId = id }
func (a *PAMApplication) SetUpdaterId(id int)     { a.UpdaterId = id }
func (a *PAMApplication) SetPerms(perms []string) { a.Permissions = perms }

type PAMAccessAudit struct {
	AccessRequestID string           `json:"access_request_id,omitempty" gorm:"size:64;index"`
	Detail          Map[string, any] `json:"detail,omitempty" gorm:"type:json"`
	Id              uint64           `json:"id" gorm:"primaryKey"`
	RequestID       string           `json:"request_id" gorm:"size:64;not null;uniqueIndex"`
	ExecutionID     string           `json:"execution_id,omitempty" gorm:"size:64;index"`
	ActorType       string           `json:"actor_type" gorm:"size:24;not null;index"`
	ActorID         int              `json:"actor_id" gorm:"not null;index"`
	ACLUID          int              `json:"acl_uid" gorm:"not null;index"`
	TargetKind      string           `json:"target_kind" gorm:"size:24;index:pam_access_target"`
	TargetID        int              `json:"target_id" gorm:"index:pam_access_target"`
	VersionID       string           `json:"version_id,omitempty" gorm:"size:64"`
	GrantID         string           `json:"grant_id,omitempty" gorm:"size:64;index"`
	Action          string           `json:"action" gorm:"size:32;not null;index"`
	Outcome         string           `json:"outcome" gorm:"size:24;not null;index"`
	ReasonCode      string           `json:"reason_code,omitempty" gorm:"size:64"`
	EvidenceID      string           `json:"evidence_id,omitempty" gorm:"size:128"`
	SourceIP        string           `json:"source_ip" gorm:"size:64"`
	CreatedAt       time.Time        `json:"created_at" gorm:"index"`
	FinishedAt      *time.Time       `json:"finished_at"`
}

func (PAMAccessAudit) TableName() string { return "pam_access_audit" }
