package model

import "time"

const (
	PAMExecutionPrepared  = "prepared"
	PAMExecutionChanging  = "changing"
	PAMExecutionVerifying = "verifying"
	PAMExecutionUnknown   = "unknown"
	PAMExecutionVerified  = "verified"
	PAMExecutionComplete  = "completed"
	PAMExecutionFailed    = "failed"
)

// PAMExecution retains one account operation and its candidate across process failures.
// ActiveAccountID is cleared only after a known outcome; expiry alone cannot unlock an uncertain change.
type PAMExecution struct {
	ID                 string     `json:"id" gorm:"size:64;primaryKey"`
	AccountID          int        `json:"account_id" gorm:"not null;index"`
	ActiveAccountID    *int       `json:"-" gorm:"uniqueIndex"`
	CreatorUID         int        `json:"creator_uid" gorm:"not null;uniqueIndex:pam_execution_request"`
	IdempotencyKey     string     `json:"-" gorm:"size:64;not null;uniqueIndex:pam_execution_request"`
	IntentHash         string     `json:"-" gorm:"size:64;not null"`
	ScopeHash          string     `json:"-" gorm:"size:64"`
	Action             string     `json:"action" gorm:"size:32;not null"`
	AccountRevision    uint64     `json:"account_revision" gorm:"not null"`
	BindingID          uint64     `json:"binding_id" gorm:"not null"`
	BindingRevision    uint64     `json:"binding_revision" gorm:"not null"`
	PreviousVersionID  string     `json:"-" gorm:"size:64;not null"`
	CandidateVersionID string     `json:"-" gorm:"size:64;not null"`
	State              string     `json:"state" gorm:"size:24;not null;index"`
	Revision           uint64     `json:"revision" gorm:"not null;default:1"`
	LeaseOwner         string     `json:"-" gorm:"size:64"`
	LeaseUntil         *time.Time `json:"-"`
	LastErrorCode      string     `json:"error_code" gorm:"size:64"`
	SourceIP           string     `json:"source_ip" gorm:"size:64"`
	SendStartedAt      *time.Time `json:"send_started_at"`
	VerifiedAt         *time.Time `json:"verified_at"`
	FinishedAt         *time.Time `json:"finished_at"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

func (PAMExecution) TableName() string { return "pam_execution" }
