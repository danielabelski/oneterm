package service

import "context"

type PAMExecutionCode string

const (
	PAMExecutionVerified       PAMExecutionCode = "verified"
	PAMExecutionChanged        PAMExecutionCode = "changed"
	PAMExecutionInvalidInput   PAMExecutionCode = "invalid_input"
	PAMExecutionAuthentication PAMExecutionCode = "authentication_failed"
	PAMExecutionIdentity       PAMExecutionCode = "target_identity_mismatch"
	PAMExecutionUnreachable    PAMExecutionCode = "unreachable"
	PAMExecutionUnsupported    PAMExecutionCode = "unsupported"
	PAMExecutionDenied         PAMExecutionCode = "permission_denied"
	PAMExecutionRejected       PAMExecutionCode = "password_rejected"
	PAMExecutionUnknown        PAMExecutionCode = "result_unknown"
)

// Transport errors can include target output or secrets; only stable codes leave an executor.
type PAMExecutionResult struct {
	Code               PAMExecutionCode `json:"code"`
	Attempted          bool             `json:"attempted"`
	ConfirmedUnchanged bool             `json:"-"`
}

// The caller persists the candidate and records the send boundary before a remote mutation.
type PAMBeforeChange func(context.Context) error
