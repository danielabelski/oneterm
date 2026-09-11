package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	"github.com/veops/oneterm/pkg/cache"
	"github.com/veops/oneterm/pkg/config"
)

var (
	ErrPAMInput       = errors.New("invalid credential access request")
	ErrPAMDenied      = errors.New("credential access is not permitted")
	ErrPAMReplay      = errors.New("credential request evidence has expired or was already used")
	ErrPAMUnavailable = errors.New("credential access is temporarily unavailable")
	ErrPAMRevision    = errors.New("the application grant changed; reload before saving")
	ErrPAMMFARequired = errors.New("MFA verification is required")
)

type PAMApplicationCredentialRequest struct {
	ApplicationID int                       `json:"application_id"`
	Target        model.PAMCredentialTarget `json:"target"`
}

type PAMCredentialResponse struct {
	ID          int    `json:"id"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Account     string `json:"account"`
	AccountType int    `json:"account_type"`
	VersionID   string `json:"version_id,omitempty"`
	Password    string `json:"password,omitempty"`
	PK          string `json:"pk,omitempty"`
	Phrase      string `json:"phrase,omitempty"`
}

type PAMApplicationService struct {
	repo *repository.PAMApplicationRepository
}

type PAMApplicationInput struct {
	Name        string                              `json:"name"`
	ACLUID      int                                 `json:"acl_uid"`
	Purpose     string                              `json:"purpose"`
	Enabled     bool                                `json:"enabled"`
	Actions     model.Slice[string]                 `json:"actions"`
	Targets     model.Map[string, model.Slice[int]] `json:"targets"`
	SourceCIDRs model.Slice[string]                 `json:"source_cidrs"`
	ExpiresAt   *time.Time                          `json:"expires_at"`
	Revision    uint64                              `json:"revision"`
}

func NewPAMApplicationService() *PAMApplicationService {
	return &PAMApplicationService{repo: repository.NewPAMApplicationRepository()}
}

func decodePAMRequest(body []byte, destination any) error {
	if len(body) == 0 || len(body) > 65536 {
		return ErrPAMInput
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrPAMInput
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrPAMInput
	}
	return nil
}

func sourceAllowed(source string, ranges []string) bool {
	address, err := netip.ParseAddr(source)
	if err != nil {
		return false
	}
	address = address.Unmap()
	if len(ranges) == 0 {
		return true
	}
	for _, value := range ranges {
		prefix, err := netip.ParsePrefix(value)
		if err == nil && prefix.Contains(address) {
			return true
		}
	}
	return false
}

func applicationAllows(application *model.PAMApplication, identity *acl.PAMKeyIdentity, target model.PAMCredentialTarget, source string, now time.Time) bool {
	if !application.Enabled || application.ACLUID != identity.ACLUID || !sourceAllowed(source, application.SourceCIDRs) {
		return false
	}
	if application.ExpiresAt != nil && !now.Before(*application.ExpiresAt) {
		return false
	}
	actionAllowed := false
	for _, action := range application.Actions {
		if action == acl.Retrieve {
			actionAllowed = true
			break
		}
	}
	if !actionAllowed {
		return false
	}
	for _, id := range application.Targets[target.Kind] {
		if id == target.ID {
			return true
		}
	}
	return false
}

func credentialResponse(owner model.CredentialOwner) *PAMCredentialResponse {
	response := &PAMCredentialResponse{ID: owner.GetId(), Kind: owner.CredentialOwnerKind(), Name: owner.GetName(),
		AccountType: owner.CredentialAuthType(), VersionID: owner.CredentialReference()}
	switch value := owner.(type) {
	case *model.Account:
		response.Account = value.Account
	case *model.Gateway:
		response.Account = value.Account
	}
	return response
}

func (s *PAMApplicationService) Retrieve(ctx context.Context, token, method, path, source string, body []byte) (response *PAMCredentialResponse, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var input PAMApplicationCredentialRequest
	if err := decodePAMRequest(body, &input); err != nil || input.ApplicationID <= 0 || input.Target.ID <= 0 {
		return nil, ErrPAMInput
	}
	if _, err := repository.CredentialOwnerModel(input.Target.Kind); err != nil {
		return nil, ErrPAMInput
	}
	identity, err := acl.VerifyPAMKey(ctx, token, method, path, body)
	if err != nil {
		return nil, err
	}
	audit := &model.PAMAccessAudit{RequestID: uuid.NewString(), ActorType: "application", ActorID: input.ApplicationID,
		ACLUID: identity.ACLUID, TargetKind: input.Target.Kind, TargetID: input.Target.ID, Action: acl.Retrieve,
		Outcome: "pending", EvidenceID: identity.ID, SourceIP: source}
	if err := s.repo.BeginAudit(ctx, audit); err != nil {
		return nil, ErrPAMUnavailable
	}
	defer func() {
		if auditErr := finishPAMAccessAudit(ctx, s.repo, audit, err); auditErr != nil {
			response, err = nil, auditErr
		}
	}()
	err = s.repo.WithApplication(ctx, input.ApplicationID, func(tx *gorm.DB, application *model.PAMApplication) error {
		now := time.Now()
		if identity.ExpiresAt <= now.Unix() {
			return ErrPAMReplay
		}
		if !applicationAllows(application, identity, input.Target, source, now) {
			return ErrPAMDenied
		}
		return repository.WithPAMPolicy(tx, input.Target, "SHARE", func(tx *gorm.DB, owner model.CredentialOwner, policy *model.PAMPolicy) error {
			if err := checkPAMOwner(ctx, tx, owner, policy, source); err != nil {
				return err
			}
			if !policy.AllowApplications || requiresPAMApproval(policy, acl.Retrieve) {
				return ErrPAMDenied
			}
			lifetime := time.Until(time.Unix(identity.ExpiresAt, 0)) + time.Second
			consumed, err := cache.RC.SetNX(ctx, "pam:key:used:"+identity.ID, "1", lifetime).Result()
			if err != nil {
				return ErrPAMUnavailable
			}
			if !consumed {
				return ErrPAMReplay
			}
			credentials, err := repository.ConfiguredCredentials()
			if err != nil {
				return ErrPAMUnavailable
			}
			material, err := credentials.ResolveInTransaction(ctx, tx, owner, []byte(config.Cfg.Auth.Aes.Iv))
			if err != nil {
				return ErrPAMUnavailable
			}
			audit.VersionID = owner.CredentialReference()
			response = credentialResponse(owner)
			response.Password, response.PK, response.Phrase = material.PasswordValue(), material.PrivateKeyValue(), material.PassphraseValue()
			return nil
		})
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = ErrPAMDenied
	} else if err != nil && !errors.Is(err, ErrPAMDenied) && !errors.Is(err, ErrPAMReplay) && !errors.Is(err, ErrPAMUnavailable) {
		err = ErrPAMUnavailable
	}
	if err != nil {
		response = nil
	}
	return
}

func PAMBearerEvidence(header string) string {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

func normalizeApplication(input *PAMApplicationInput, now time.Time) error {
	input.Name, input.Purpose = strings.TrimSpace(input.Name), strings.TrimSpace(input.Purpose)
	if input.ACLUID <= 0 || input.Name == "" || utf8.RuneCountInString(input.Name) > 128 ||
		input.Purpose == "" || utf8.RuneCountInString(input.Purpose) > 1024 {
		return ErrPAMInput
	}
	if len(input.Actions) > 1 {
		return ErrPAMInput
	}
	for _, action := range input.Actions {
		if action != acl.Retrieve {
			return ErrPAMInput
		}
	}
	if input.Actions == nil {
		input.Actions = model.Slice[string]{}
	}
	if input.Targets == nil {
		input.Targets = model.Map[string, model.Slice[int]]{}
	}
	count := 0
	for kind, ids := range input.Targets {
		if _, err := repository.CredentialOwnerModel(kind); err != nil {
			return ErrPAMInput
		}
		seen := make(map[int]bool)
		normalized := make(model.Slice[int], 0, len(ids))
		for _, id := range ids {
			if id <= 0 {
				return ErrPAMInput
			}
			if !seen[id] {
				normalized = append(normalized, id)
				seen[id] = true
			}
		}
		sort.Ints(normalized)
		input.Targets[kind] = normalized
		count += len(normalized)
	}
	if count > 1000 || len(input.SourceCIDRs) > 100 {
		return ErrPAMInput
	}
	if input.Enabled && (len(input.Actions) == 0 || count == 0) {
		return ErrPAMInput
	}
	if input.Enabled && input.ExpiresAt != nil && !now.Before(*input.ExpiresAt) {
		return ErrPAMInput
	}
	ranges := make(model.Slice[string], 0, len(input.SourceCIDRs))
	seenRanges := make(map[string]bool)
	for _, value := range input.SourceCIDRs {
		value = strings.TrimSpace(value)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil || address.Zone() != "" {
				return ErrPAMInput
			}
			address = address.Unmap()
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		value = prefix.Masked().String()
		if !seenRanges[value] {
			ranges = append(ranges, value)
			seenRanges[value] = true
		}
	}
	input.SourceCIDRs = ranges
	return nil
}

func (s *PAMApplicationService) validateGrant(ctx context.Context, input *PAMApplicationInput, operator *acl.Session) error {
	if err := normalizeApplication(input, time.Now()); err != nil {
		return err
	}
	subject, err := acl.GetPAMKeySubject(ctx, input.ACLUID)
	if err != nil {
		return err
	}
	if input.Enabled && subject.Blocked {
		return ErrPAMInput
	}
	for kind, ids := range input.Targets {
		if len(ids) == 0 {
			continue
		}
		resources, err := s.repo.TargetResources(ctx, kind, ids)
		if err != nil {
			return ErrPAMUnavailable
		}
		if len(resources) != len(ids) {
			return ErrPAMInput
		}
		if acl.IsAdmin(operator) {
			continue
		}
		permissions, err := acl.GetRoleResources(ctx, operator.GetRid(), kind)
		if err != nil {
			return ErrPAMUnavailable
		}
		grantable := make(map[int]bool)
		for _, resource := range permissions {
			for _, action := range resource.Permissions {
				if action == acl.GRANT {
					grantable[resource.ResourceId] = true
				}
			}
		}
		for _, resource := range resources {
			if !grantable[resource.ResourceID] {
				return ErrPAMDenied
			}
		}
	}
	return nil
}

func applicationFromInput(input PAMApplicationInput) *model.PAMApplication {
	return &model.PAMApplication{Name: input.Name, ACLUID: input.ACLUID, Purpose: input.Purpose, Enabled: input.Enabled,
		Actions: input.Actions, Targets: input.Targets, SourceCIDRs: input.SourceCIDRs, ExpiresAt: input.ExpiresAt, Revision: 1}
}

func (s *PAMApplicationService) Create(ctx *gin.Context, body []byte) (application *model.PAMApplication, err error) {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil || !acl.IsAdmin(operator) {
		return nil, ErrPAMDenied
	}
	if !acl.VerifyMFAToken(ctx.Request.Context(), operator, ctx.GetHeader("X-MFA-Token"), acl.PAMMFAPolicy) {
		return nil, ErrPAMMFARequired
	}
	var input PAMApplicationInput
	if err := decodePAMRequest(body, &input); err != nil {
		return nil, err
	}
	if err := s.validateGrant(ctx.Request.Context(), &input, operator); err != nil {
		return nil, err
	}
	application = applicationFromInput(input)
	application.CreatorId, application.UpdaterId = operator.Uid, operator.Uid
	resourceID := 0
	err = s.repo.Transaction(ctx.Request.Context(), func(tx *gorm.DB) error {
		if err := tx.Create(application).Error; err != nil {
			return err
		}
		requestCtx, cancel := context.WithTimeout(ctx.Request.Context(), 5*time.Second)
		defer cancel()
		var err error
		resourceID, err = acl.CreateGrantAcl(requestCtx, operator, config.RESOURCE_PAM_APPLICATION, uuid.NewString())
		if err != nil {
			return err
		}
		application.ResourceId = resourceID
		if err := tx.Model(application).Update("resource_id", resourceID).Error; err != nil {
			return err
		}
		history := NewHistoryService().CreateHistoryRecord(ctx, model.ACTION_CREATE, application, nil, operator.Uid)
		return tx.Create(history).Error
	})
	if err != nil {
		if resourceID > 0 {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx.Request.Context()), 5*time.Second)
			defer cancel()
			if cleanupErr := acl.DeleteResource(cleanupCtx, operator.Uid, resourceID); cleanupErr != nil {
				return nil, ErrPAMUnavailable
			}
		}
		return nil, err
	}
	return application, nil
}

func (s *PAMApplicationService) Update(ctx *gin.Context, id int, body []byte) (*model.PAMApplication, error) {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil {
		return nil, ErrPAMDenied
	}
	current, err := s.repo.Get(ctx.Request.Context(), id)
	if err != nil {
		return nil, err
	}
	if !acl.IsAdmin(operator) {
		allowed, err := acl.HasPermission(ctx.Request.Context(), operator.GetRid(), config.RESOURCE_PAM_APPLICATION, current.ResourceId, acl.WRITE)
		if err != nil || !allowed {
			return nil, ErrPAMDenied
		}
	}
	if !acl.VerifyMFAToken(ctx.Request.Context(), operator, ctx.GetHeader("X-MFA-Token"), acl.PAMMFAPolicy) {
		return nil, ErrPAMMFARequired
	}
	var input PAMApplicationInput
	if err := decodePAMRequest(body, &input); err != nil {
		return nil, err
	}
	if input.Revision == 0 || input.ACLUID != current.ACLUID {
		return nil, ErrPAMInput
	}
	if err := s.validateGrant(ctx.Request.Context(), &input, operator); err != nil {
		return nil, err
	}
	var updated *model.PAMApplication
	err = s.repo.WithApplication(ctx.Request.Context(), id, func(tx *gorm.DB, locked *model.PAMApplication) error {
		if locked.Revision != input.Revision {
			return ErrPAMRevision
		}
		updated = applicationFromInput(input)
		updated.Id, updated.ResourceId = locked.Id, locked.ResourceId
		updated.CreatorId, updated.UpdaterId = locked.CreatorId, operator.Uid
		updated.CreatedAt, updated.Revision = locked.CreatedAt, locked.Revision+1
		if err := tx.Select("name", "purpose", "enabled", "actions", "targets", "source_cidrs", "expires_at", "revision", "updater_id", "updated_at").Save(updated).Error; err != nil {
			return err
		}
		history := NewHistoryService().CreateHistoryRecord(ctx, model.ACTION_UPDATE, updated, locked, operator.Uid)
		return tx.Create(history).Error
	})
	return updated, err
}

func (s *PAMApplicationService) Query(ctx *gin.Context) *gorm.DB {
	query := s.repo.Query(ctx.Request.Context())
	if search := strings.TrimSpace(ctx.Query("search")); search != "" {
		query = query.Where("name LIKE ? OR purpose LIKE ?", "%"+search+"%", "%"+search+"%")
	}
	if enabled := ctx.Query("enabled"); enabled == "true" || enabled == "false" {
		query = query.Where("enabled = ?", enabled == "true")
	}
	return query
}

// Disable only needs authority over the application, not renewed authority over its old targets.
func (s *PAMApplicationService) Disable(ctx *gin.Context, id int, revision uint64) (*model.PAMApplication, error) {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil || revision == 0 {
		return nil, ErrPAMDenied
	}
	current, err := s.repo.Get(ctx.Request.Context(), id)
	if err != nil {
		return nil, err
	}
	if !acl.IsAdmin(operator) {
		allowed, err := acl.HasPermission(ctx.Request.Context(), operator.GetRid(), config.RESOURCE_PAM_APPLICATION, current.ResourceId, acl.WRITE)
		if err != nil || !allowed {
			return nil, ErrPAMDenied
		}
	}
	if !acl.VerifyMFAToken(ctx.Request.Context(), operator, ctx.GetHeader("X-MFA-Token"), acl.PAMMFAPolicy) {
		return nil, ErrPAMMFARequired
	}
	var updated *model.PAMApplication
	err = s.repo.WithApplication(ctx.Request.Context(), id, func(tx *gorm.DB, locked *model.PAMApplication) error {
		if locked.Revision != revision {
			return ErrPAMRevision
		}
		copy := *locked
		updated = &copy
		if !locked.Enabled {
			return nil
		}
		updated.Enabled, updated.Revision, updated.UpdaterId = false, locked.Revision+1, operator.Uid
		if err := tx.Select("enabled", "revision", "updater_id", "updated_at").Save(updated).Error; err != nil {
			return err
		}
		return tx.Create(NewHistoryService().CreateHistoryRecord(ctx, model.ACTION_UPDATE, updated, locked, operator.Uid)).Error
	})
	return updated, err
}

func (s *PAMApplicationService) TargetQuery(ctx *gin.Context, kind string) (*gorm.DB, error) {
	operator, err := acl.GetSessionFromCtx(ctx)
	if err != nil {
		return nil, ErrPAMDenied
	}
	query, err := s.repo.TargetQuery(ctx.Request.Context(), kind)
	if err != nil {
		return nil, ErrPAMInput
	}
	if !acl.IsAdmin(operator) {
		resources, err := acl.GetRoleResources(ctx.Request.Context(), operator.GetRid(), kind)
		if err != nil {
			return nil, ErrPAMUnavailable
		}
		ids := make([]int, 0, len(resources))
		for _, resource := range resources {
			for _, action := range resource.Permissions {
				if action == acl.GRANT {
					ids = append(ids, resource.ResourceId)
					break
				}
			}
		}
		query = query.Where("resource_id IN ?", ids)
	}
	if search := strings.TrimSpace(ctx.Query("search")); search != "" {
		query = query.Where("name LIKE ? OR account LIKE ?", "%"+search+"%", "%"+search+"%")
	}
	if raw := ctx.Query("ids"); raw != "" {
		var ids []int
		for _, value := range strings.Split(raw, ",") {
			id, err := strconv.Atoi(value)
			if err != nil || id <= 0 {
				return nil, ErrPAMInput
			}
			ids = append(ids, id)
		}
		if len(ids) > 200 {
			return nil, ErrPAMInput
		}
		query = query.Where("id IN ?", ids)
	}
	return query, nil
}
