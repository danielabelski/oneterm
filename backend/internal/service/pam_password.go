package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	"github.com/veops/oneterm/pkg/config"
	"github.com/veops/oneterm/pkg/db"
	"github.com/veops/oneterm/pkg/secret"
)

var pamPasswordSlots = make(chan struct{}, 4)

type PAMPasswordConfig struct {
	Protocol          string `json:"protocol"`
	SSHHostKey        string `json:"ssh_host_key"`
	TLSCA             string `json:"tls_ca"`
	TLSServerName     string `json:"tls_server_name"`
	ExecutorAccountID int    `json:"executor_account_id"`
	UseSudo           bool   `json:"use_sudo"`
}

type PAMPasswordConfigInput struct {
	Revision uint64 `json:"revision"`
	PAMPasswordConfig
}

type PAMPasswordInput struct {
	BindingID          uint64 `json:"binding_id"`
	BindingRevision    uint64 `json:"binding_revision"`
	CredentialRevision uint64 `json:"credential_revision"`
	IdempotencyKey     string `json:"idempotency_key"`
	Password           string `json:"password"`
	Action             string `json:"action"`
}

type PAMOriginalConfirmation struct {
	Revision      uint64 `json:"revision"`
	RemoteStopped bool   `json:"remote_stopped"`
}

func ParsePAMOriginalConfirmation(body []byte) (PAMOriginalConfirmation, error) {
	var input PAMOriginalConfirmation
	err := decodePAMRequest(body, &input)
	if input.Revision == 0 || !input.RemoteStopped {
		err = ErrPAMInput
	}
	return input, err
}

type pamPasswordTarget struct {
	account *model.Account
	binding *model.PAMAssetAccountBinding
	asset   *model.Asset
	config  PAMPasswordConfig
	address string
}

func (target *pamPasswordTarget) scopeHash() string {
	identity := target.config
	identity.ExecutorAccountID, identity.UseSudo = 0, false
	data, _ := json.Marshal(struct {
		AssetID   int
		NativeKey string
		Host      string
		Gateway   int
		Identity  PAMPasswordConfig
	}{target.binding.AssetID, target.account.NativeKey, target.binding.TargetHost, target.binding.GatewayID, identity})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (target *pamPasswordTarget) matchesExecution(execution *model.PAMExecution, recovery bool) bool {
	if recovery && execution.ScopeHash != "" {
		return execution.ScopeHash == target.scopeHash()
	}
	return target.binding.Revision == execution.BindingRevision && target.account.Revision == execution.AccountRevision
}

func ParsePAMPasswordConfig(body []byte) (PAMPasswordConfigInput, error) {
	var input PAMPasswordConfigInput
	err := decodePAMRequest(body, &input)
	if input.Revision == 0 {
		err = ErrPAMInput
	}
	return input, err
}

func ParsePAMPasswordInput(body []byte) (PAMPasswordInput, error) {
	var input PAMPasswordInput
	err := decodePAMRequest(body, &input)
	if input.BindingID == 0 || input.BindingRevision == 0 || len(input.Password) > 1024 || strings.ContainsAny(input.Password, "\x00\r\n") {
		err = ErrPAMInput
	}
	return input, err
}

func loadPAMPasswordTarget(ctx context.Context, accountID int, bindingID uint64) (*pamPasswordTarget, error) {
	result := &pamPasswordTarget{account: &model.Account{Managed: true}, binding: &model.PAMAssetAccountBinding{}, asset: &model.Asset{}}
	database := db.GetDB().WithContext(ctx)
	if err := database.Where("managed = ?", true).First(result.account, accountID).Error; err != nil {
		return nil, err
	}
	if err := database.Where("id = ? AND account_id = ?", bindingID, accountID).First(result.binding).Error; err != nil {
		return nil, err
	}
	if err := database.First(result.asset, result.binding.AssetID).Error; err != nil {
		return nil, err
	}
	if !result.account.Enabled || !result.binding.Enabled || !repository.BindingMatchesAsset(result.binding, result.asset) {
		return nil, repository.ErrPAMBindingChanged
	}
	data, err := json.Marshal(result.binding.PasswordConfig)
	if err != nil || json.Unmarshal(data, &result.config) != nil {
		return nil, ErrPAMInput
	}
	return result, nil
}

func pamPasswordCA(value string) (*x509.CertPool, error) {
	if value == "" {
		return nil, nil
	}
	if len(value) > 49152 {
		return nil, ErrPAMInput
	}
	pool := x509.NewCertPool()
	rest := []byte(strings.TrimSpace(value))
	for len(rest) > 0 {
		if !strings.HasPrefix(string(rest), "-----BEGIN CERTIFICATE-----") {
			return nil, ErrPAMInput
		}
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) > 0 {
			return nil, ErrPAMInput
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrPAMInput
		}
		pool.AddCert(certificate)
		rest = []byte(strings.TrimSpace(string(next)))
	}
	return pool, nil
}

func (target *pamPasswordTarget) validate() error {
	platform, exists := PAMPlatform(target.account.Platform)
	if !exists || (target.account.Platform != "mysql" && target.account.Platform != "linux_local") || target.binding.GatewayID != 0 {
		return ErrPAMProviderUnavailable
	}
	protocol, port, ok := strings.Cut(target.config.Protocol, ":")
	number, err := strconv.Atoi(port)
	if !ok || err != nil || number < 1 || number > 65535 || protocol != platform.Protocol {
		return ErrPAMInput
	}
	matched := false
	for _, value := range target.binding.Protocols {
		matched = matched || value == target.config.Protocol
	}
	if !matched || target.config.ExecutorAccountID < 0 {
		return ErrPAMInput
	}
	host := target.asset.Ip
	if parsed, explicitPort, splitErr := net.SplitHostPort(host); splitErr == nil {
		if explicitPort != port {
			return ErrPAMInput
		}
		host = parsed
	}
	if host == "" {
		return ErrPAMInput
	}
	target.address = net.JoinHostPort(host, port)
	if target.account.Platform == "linux_local" {
		if target.config.TLSCA != "" || target.config.TLSServerName != "" {
			return ErrPAMInput
		}
		_, err := pamSSHConfig(target.linux(), target.account.Account, secret.NewPassword("validation-only"))
		return err
	}
	if target.config.SSHHostKey != "" || target.config.UseSudo {
		return ErrPAMInput
	}
	databaseTarget, err := target.mysql()
	if err != nil {
		return err
	}
	_, err = pamMySQLConfig(databaseTarget, databaseTarget.Account, secret.NewPassword("validation-only"))
	return err
}

func (target *pamPasswordTarget) linux() PAMLinuxTarget {
	return PAMLinuxTarget{Address: target.address, Username: target.account.Account,
		HostKeyFingerprint: target.config.SSHHostKey, UseSudo: target.config.UseSudo}
}

func (target *pamPasswordTarget) mysql() (PAMMySQLTarget, error) {
	pool, err := pamPasswordCA(target.config.TLSCA)
	if err != nil {
		return PAMMySQLTarget{}, err
	}
	host, _, err := net.SplitHostPort(target.address)
	if err != nil {
		return PAMMySQLTarget{}, ErrPAMInput
	}
	name := target.config.TLSServerName
	if name == "" {
		name = host
	}
	return PAMMySQLTarget{Address: target.address, TLS: &tls.Config{RootCAs: pool, ServerName: name, MinVersion: tls.VersionTLS12},
		Account: PAMMySQLAccount{Username: target.account.Account, Host: target.account.NativeQualifier}}, nil
}

func (target *pamPasswordTarget) actor(ctx context.Context) (*model.Account, error) {
	if target.config.ExecutorAccountID == 0 || target.config.ExecutorAccountID == target.account.Id {
		return target.account, nil
	}
	var binding model.PAMAssetAccountBinding
	if err := db.GetDB().WithContext(ctx).Where("asset_id = ? AND account_id = ? AND enabled = ?",
		target.asset.Id, target.config.ExecutorAccountID, true).First(&binding).Error; err != nil {
		return nil, ErrPAMDenied
	}
	if !repository.BindingMatchesAsset(&binding, target.asset) {
		return nil, repository.ErrPAMBindingChanged
	}
	var actor model.Account
	if err := db.GetDB().WithContext(ctx).Where("managed = ?", true).First(&actor, binding.AccountID).Error; err != nil {
		return nil, err
	}
	if !actor.Enabled || actor.Platform != target.account.Platform {
		return nil, ErrPAMDenied
	}
	return &actor, nil
}

func SavePAMPasswordConfig(ctx *gin.Context, accountID int, bindingID uint64, input PAMPasswordConfigInput) (*model.PAMAssetAccountBinding, error) {
	target, err := loadPAMPasswordTarget(ctx.Request.Context(), accountID, bindingID)
	if err != nil {
		return nil, err
	}
	target.config = input.PAMPasswordConfig
	if err := target.validate(); err != nil {
		return nil, err
	}
	actor, err := target.actor(ctx.Request.Context())
	if err != nil {
		return nil, err
	}
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil {
		return nil, ErrPAMDenied
	}
	for _, owner := range []*model.Account{target.account, actor} {
		for _, action := range []string{acl.ManagePolicy, acl.GRANT} {
			allowed, err := pamResourcePermission(ctx.Request.Context(), operator, owner, action, true)
			if err != nil || !allowed {
				return nil, ErrPAMDenied
			}
		}
	}
	encoded, _ := json.Marshal(target.config)
	var values model.Map[string, any]
	if err := json.Unmarshal(encoded, &values); err != nil {
		return nil, ErrPAMInput
	}
	err = db.GetDB().WithContext(ctx.Request.Context()).Transaction(func(tx *gorm.DB) error {
		var current model.PAMAssetAccountBinding
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND account_id = ?", bindingID, accountID).First(&current).Error; err != nil {
			return err
		}
		if current.Revision != input.Revision {
			return ErrPAMRevision
		}
		before := current
		current.PasswordConfig, current.Revision, current.UpdaterID = values, current.Revision+1, operator.Uid
		if err := tx.Save(&current).Error; err != nil {
			return err
		}
		history := NewHistoryService().CreateHistoryRecord(ctx, model.ACTION_UPDATE, target.account, target.account, operator.Uid)
		history.Old["password_config"], history.New["password_config"] = before.PasswordConfig, current.PasswordConfig
		if err := tx.Create(history).Error; err != nil {
			return err
		}
		target.binding = &current
		return nil
	})
	return target.binding, err
}

func authorizePAMPassword(ctx context.Context, operator *acl.Session, target *pamPasswordTarget, action, source string) error {
	allowed, err := pamResourcePermission(ctx, operator, target.account, action, true)
	if err != nil || !allowed {
		return ErrPAMDenied
	}
	policy, err := NewPAMPolicyService().Get(ctx, model.PAMCredentialTarget{Kind: model.PAMOwnerAccount, ID: target.account.Id})
	if err != nil {
		return err
	}
	if err := checkPAMOwner(ctx, db.GetDB().WithContext(ctx), target.account, policy, source); err != nil {
		return err
	}
	if action != acl.VerifySecret && requiresPAMApproval(policy, action) {
		return ErrPAMApprovalRequired
	}
	if action == acl.RotateSecret || action == acl.RecoverSecret {
		return validatePAMAccountScope(ctx, db.GetDB(), target.account, target.asset.Id)
	}
	return nil
}

func (target *pamPasswordTarget) verify(ctx context.Context, material secret.Material) PAMExecutionResult {
	if target.account.Platform == "linux_local" {
		return (PAMLinuxExecutor{}).Verify(ctx, target.linux(), material)
	}
	database, err := target.mysql()
	if err != nil {
		return PAMExecutionResult{Code: PAMExecutionInvalidInput}
	}
	return (PAMMySQLExecutor{}).Verify(ctx, database, material)
}

func (target *pamPasswordTarget) change(ctx context.Context, current, candidate secret.Material, before PAMBeforeChange) PAMExecutionResult {
	actor, err := target.actor(ctx)
	if err != nil {
		return PAMExecutionResult{Code: PAMExecutionDenied}
	}
	if actor.Id != target.account.Id {
		credentials, err := repository.ConfiguredCredentials()
		if err != nil {
			return PAMExecutionResult{Code: PAMExecutionUnreachable}
		}
		current, err = credentials.ReadActive(ctx, model.PAMOwnerAccount, actor.Id, actor.CredentialVersionID)
		if err != nil {
			return PAMExecutionResult{Code: PAMExecutionUnreachable}
		}
	}
	if target.account.Platform == "linux_local" {
		return (PAMLinuxExecutor{}).Change(ctx, target.linux(), actor.Account, current, candidate, before)
	}
	database, err := target.mysql()
	if err != nil {
		return PAMExecutionResult{Code: PAMExecutionInvalidInput}
	}
	return (PAMMySQLExecutor{}).Change(ctx, database, PAMMySQLAccount{Username: actor.Account, Host: actor.NativeQualifier}, current, candidate, before)
}

func VerifyPAMPassword(ctx *gin.Context, accountID int, input PAMPasswordInput) (PAMExecutionResult, error) {
	target, err := loadPAMPasswordTarget(ctx.Request.Context(), accountID, input.BindingID)
	if err != nil {
		return PAMExecutionResult{}, err
	}
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil {
		return PAMExecutionResult{}, ErrPAMDenied
	}
	if err := authorizePAMPassword(ctx.Request.Context(), operator, target, acl.VerifySecret, ctx.ClientIP()); err != nil {
		return PAMExecutionResult{}, err
	}
	if target.binding.Revision != input.BindingRevision || target.account.CredentialRevision != input.CredentialRevision {
		return PAMExecutionResult{}, ErrPAMRevision
	}
	if err := target.validate(); err != nil {
		return PAMExecutionResult{}, err
	}
	select {
	case pamPasswordSlots <- struct{}{}:
		defer func() { <-pamPasswordSlots }()
	default:
		return PAMExecutionResult{}, repository.ErrPAMExecutionState
	}
	audit := &model.PAMAccessAudit{RequestID: uuid.NewString(), ActorType: "user", ActorID: operator.Uid, ACLUID: operator.Uid,
		TargetKind: model.PAMOwnerAccount, TargetID: accountID, Action: acl.VerifySecret, Outcome: "pending", SourceIP: ctx.ClientIP()}
	if err := db.GetDB().WithContext(ctx.Request.Context()).Create(audit).Error; err != nil {
		return PAMExecutionResult{}, err
	}
	result := PAMExecutionResult{Code: PAMExecutionUnreachable}
	credentials, err := repository.ConfiguredCredentials()
	if err == nil {
		var material secret.Material
		material, err = credentials.ReadActive(ctx.Request.Context(), model.PAMOwnerAccount, accountID, target.account.CredentialVersionID)
		if err == nil {
			result = target.verify(ctx.Request.Context(), material)
		}
	}
	outcome := "failed"
	if result.Code == PAMExecutionVerified {
		outcome = "succeeded"
	}
	save, cancel := context.WithTimeout(context.WithoutCancel(ctx.Request.Context()), 5*time.Second)
	defer cancel()
	if err := db.GetDB().WithContext(save).Model(audit).Updates(map[string]any{"outcome": outcome,
		"reason_code": string(result.Code), "finished_at": time.Now(), "version_id": target.account.CredentialVersionID}).Error; err != nil {
		return result, ErrPAMUnavailable
	}
	return result, err
}

func StartPAMPasswordChange(ctx *gin.Context, accountID int, input PAMPasswordInput) (*model.PAMExecution, error) {
	if input.Action != acl.RotateSecret && input.Action != acl.RecoverSecret {
		return nil, ErrPAMInput
	}
	if input.IdempotencyKey == "" || len(input.IdempotencyKey) > 64 {
		return nil, ErrPAMInput
	}
	target, err := loadPAMPasswordTarget(ctx.Request.Context(), accountID, input.BindingID)
	if err != nil {
		return nil, err
	}
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil {
		return nil, ErrPAMDenied
	}
	if err := authorizePAMPassword(ctx.Request.Context(), operator, target, input.Action, ctx.ClientIP()); err != nil {
		return nil, err
	}
	if err := target.validate(); err != nil {
		return nil, err
	}
	if input.Action == acl.RecoverSecret && (target.config.ExecutorAccountID == 0 || target.config.ExecutorAccountID == accountID) {
		return nil, ErrPAMInput
	}
	select {
	case pamPasswordSlots <- struct{}{}:
		defer func() { <-pamPasswordSlots }()
	default:
		return nil, repository.ErrPAMExecutionState
	}
	intent, _ := json.Marshal(struct {
		Account int
		Input   PAMPasswordInput
	}{accountID, input})
	digest := hmac.New(sha256.New, []byte(config.Cfg.Auth.Aes.Key))
	digest.Write([]byte("oneterm:password-operation:v1\x00"))
	digest.Write(intent)
	intentHash := hex.EncodeToString(digest.Sum(nil))
	var existing model.PAMExecution
	lookup := db.GetDB().WithContext(ctx.Request.Context()).Where("creator_uid = ? AND idempotency_key = ?", operator.Uid, input.IdempotencyKey)
	if err := lookup.First(&existing).Error; err == nil {
		if existing.IntentHash != intentHash {
			return nil, ErrPAMRevision
		}
		return &existing, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if target.binding.Revision != input.BindingRevision || target.account.CredentialRevision != input.CredentialRevision {
		return nil, ErrPAMRevision
	}
	value := input.Password
	if value == "" {
		random := make([]byte, 24)
		if _, err := rand.Read(random); err != nil {
			return nil, err
		}
		value = base64.RawURLEncoding.EncodeToString(random) + "aA1!"
	}
	credentials, err := repository.ConfiguredCredentials()
	if err != nil {
		return nil, err
	}
	store := repository.NewPAMExecutionRepository(db.GetDB(), credentials)
	execution, err := store.Prepare(ctx.Request.Context(), model.PAMExecution{AccountID: accountID, CreatorUID: operator.Uid,
		IdempotencyKey: input.IdempotencyKey, IntentHash: intentHash, Action: input.Action,
		ScopeHash:       target.scopeHash(),
		AccountRevision: target.account.Revision, BindingID: target.binding.ID, BindingRevision: target.binding.Revision,
		PreviousVersionID: target.account.CredentialVersionID, SourceIP: ctx.ClientIP()}, secret.NewPassword(value))
	if err != nil {
		return nil, err
	}
	return executePAMPassword(ctx, target, execution, false, input.Action)
}

func executePAMPassword(ctx *gin.Context, target *pamPasswordTarget, execution *model.PAMExecution, reconcile bool, action string) (*model.PAMExecution, error) {
	operator, _ := acl.GetSessionFromCtx(ctx)
	source := ctx.ClientIP()
	_, runErr := RunPAMExecution(ctx.Request.Context(), execution.ID, reconcile, func(requestCtx context.Context, current *model.PAMExecution) error {
		latest, err := loadPAMPasswordTarget(requestCtx, current.AccountID, current.BindingID)
		if err != nil {
			return err
		}
		if !latest.matchesExecution(current, reconcile) {
			return ErrPAMRevision
		}
		return authorizePAMPassword(requestCtx, operator, latest, action, source)
	}, target.change, target.verify)
	save, cancel := context.WithTimeout(context.WithoutCancel(ctx.Request.Context()), 5*time.Second)
	defer cancel()
	if err := db.GetDB().WithContext(save).Where("id = ?", execution.ID).First(execution).Error; err != nil {
		return nil, err
	}
	// Always return the durable operation, including uncertain results, rather than losing its recovery identity.
	if runErr != nil {
		return execution, runErr
	}
	return execution, nil
}

func ContinuePAMPassword(ctx *gin.Context, accountID int, id string, operation string) (result *model.PAMExecution, err error) {
	reconcile := operation != "resume"
	var execution model.PAMExecution
	if err := db.GetDB().WithContext(ctx.Request.Context()).Where("id = ? AND account_id = ?", id, accountID).First(&execution).Error; err != nil {
		return nil, err
	}
	target, err := loadPAMPasswordTarget(ctx.Request.Context(), accountID, execution.BindingID)
	if err != nil {
		return nil, err
	}
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil {
		return nil, ErrPAMDenied
	}
	action := acl.RecoverSecret
	if !reconcile {
		if execution.State != model.PAMExecutionPrepared {
			return nil, repository.ErrPAMExecutionState
		}
		action = execution.Action
	}
	if err := authorizePAMPassword(ctx.Request.Context(), operator, target, action, ctx.ClientIP()); err != nil {
		return nil, err
	}
	if execution.State == model.PAMExecutionComplete {
		return &execution, nil
	}
	if err := target.validate(); err != nil {
		return nil, err
	}
	if !target.matchesExecution(&execution, reconcile) {
		return nil, ErrPAMRevision
	}
	select {
	case pamPasswordSlots <- struct{}{}:
		defer func() { <-pamPasswordSlots }()
	default:
		return nil, repository.ErrPAMExecutionState
	}
	auditAction := execution.Action
	if reconcile {
		auditAction = "reconcile_secret"
	}
	if operation == "keep-original" {
		auditAction = "preserve_original_secret"
	}
	audit := &model.PAMAccessAudit{RequestID: uuid.NewString(), ExecutionID: id, ActorType: "user", ActorID: operator.Uid,
		ACLUID: operator.Uid, TargetKind: model.PAMOwnerAccount, TargetID: accountID,
		Action: auditAction, Outcome: "pending", SourceIP: ctx.ClientIP()}
	if err := db.GetDB().WithContext(ctx.Request.Context()).Create(audit).Error; err != nil {
		return nil, err
	}
	defer func() {
		outcome, reason := "failed", "not_completed"
		if err == nil && result != nil && (result.State == model.PAMExecutionComplete || result.LastErrorCode == "original_verified") {
			outcome, reason = "succeeded", ""
		}
		save, cancel := context.WithTimeout(context.WithoutCancel(ctx.Request.Context()), 5*time.Second)
		defer cancel()
		if saveErr := db.GetDB().WithContext(save).Model(audit).Updates(map[string]any{"outcome": outcome,
			"reason_code": reason, "finished_at": time.Now()}).Error; saveErr != nil {
			err = ErrPAMUnavailable
		}
	}()
	if operation == "keep-original" {
		return preservePAMOriginal(ctx.Request.Context(), target, &execution, operator, ctx.ClientIP())
	}
	return executePAMPassword(ctx, target, &execution, reconcile, action)
}

func preservePAMOriginal(ctx context.Context, target *pamPasswordTarget, execution *model.PAMExecution, operator *acl.Session, source string) (*model.PAMExecution, error) {
	credentials, err := repository.ConfiguredCredentials()
	if err != nil {
		return nil, err
	}
	store := repository.NewPAMExecutionRepository(db.GetDB(), credentials)
	owner := uuid.NewString()
	claimed, err := store.Claim(ctx, execution.ID, owner, true)
	if err != nil {
		return nil, err
	}
	target, err = loadPAMPasswordTarget(ctx, claimed.AccountID, claimed.BindingID)
	if err != nil {
		return nil, err
	}
	if err := target.validate(); err != nil {
		return nil, err
	}
	if !target.matchesExecution(claimed, true) {
		return nil, ErrPAMRevision
	}
	if err := authorizePAMPassword(ctx, operator, target, acl.RecoverSecret, source); err != nil {
		return nil, err
	}
	material, err := credentials.ReadActive(ctx, model.PAMOwnerAccount, claimed.AccountID, claimed.PreviousVersionID)
	if err != nil {
		return nil, err
	}
	if result := target.verify(ctx, material); result.Code != PAMExecutionVerified {
		return nil, ErrPAMUnavailable
	}
	save, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := store.PreserveOriginal(save, claimed.ID, owner); err != nil {
		return nil, err
	}
	if err := db.GetDB().WithContext(save).Where("id = ?", claimed.ID).First(claimed).Error; err != nil {
		return nil, err
	}
	return claimed, nil
}
