package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/pkg/config"
	"github.com/veops/oneterm/pkg/logger"
)

var ErrPAMTemplateDenied = errors.New("the current user cannot initiate this approval template")

var pamITSMHTTP = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}}

type PAMITSMTemplate struct {
	TemplateID       int                      `json:"template_id"`
	TemplateName     string                   `json:"template_name"`
	TemplateRevision string                   `json:"template_revision"`
	NodeID           int                      `json:"node_id"`
	FormConfig       model.Map[string, any]   `json:"form_config"`
	Buttons          []model.Map[string, any] `json:"buttons"`
}

type PAMITSMStatus struct {
	RequestID        string           `json:"request_id"`
	RequestRevision  uint64           `json:"request_revision"`
	TicketID         int              `json:"ticket_id"`
	TemplateID       int              `json:"template_id"`
	TemplateRevision string           `json:"template_revision"`
	InitState        string           `json:"init_state"`
	Decision         string           `json:"decision"`
	ProviderRevision uint64           `json:"provider_revision"`
	Event            *PAMITSMDecision `json:"event"`
}

type pamITSMRemoteError struct {
	Status int
	Code   string
}

func (e *pamITSMRemoteError) Error() string {
	return fmt.Sprintf("ITSM bridge rejected request: status=%d code=%s", e.Status, e.Code)
}

func callPAMITSM(ctx context.Context, operation string, payload any, result any) error {
	endpoint, err := url.Parse(config.Cfg.Auth.Acl.Url)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" ||
		(endpoint.Scheme != "http" && endpoint.Scheme != "https") || !strings.HasSuffix(strings.TrimSuffix(endpoint.Path, "/"), "/api/v1") {
		return ErrPAMProviderUnavailable
	}
	switch operation {
	case "template", "templates", "create", "status", "cancel":
	default:
		return ErrPAMInput
	}
	endpoint.Path = strings.TrimSuffix(strings.TrimSuffix(endpoint.Path, "/"), "/api/v1") + "/api/itsm/v1/pam/service/" + operation
	endpoint.RawPath, endpoint.Fragment = "", ""
	body, err := json.Marshal(payload)
	if err != nil {
		return ErrPAMInput
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return ErrPAMProviderUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	nonce, err := acl.SignPAMServiceRequest(config.Cfg.SecretKey, request, body)
	if err != nil {
		return ErrPAMProviderUnavailable
	}
	response, err := pamITSMHTTP.Do(request)
	if err != nil {
		return ErrPAMUnavailable
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1048577))
	if err != nil || len(data) > 1048576 || !acl.VerifyPAMServiceResponse(config.Cfg.SecretKey, nonce, response, data) {
		return ErrPAMUnavailable
	}
	if response.StatusCode != http.StatusOK {
		var failure struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(data, &failure)
		// Do not propagate upstream messages or arbitrary payload content into logs.
		switch failure.Code {
		case "invalid_payload", "request_rejected", "unsupported_operation", "internal_error":
		default:
			failure.Code = "unknown"
		}
		logger.L().Warn("ITSM bridge rejected operation", zap.String("operation", operation),
			zap.Int("status", response.StatusCode), zap.String("code", failure.Code))
		return &pamITSMRemoteError{Status: response.StatusCode, Code: failure.Code}
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil || len(envelope.Data) == 0 {
		return ErrPAMUnavailable
	}
	if err := json.Unmarshal(envelope.Data, result); err != nil {
		return ErrPAMUnavailable
	}
	return nil
}

func describePAMITSMTemplate(ctx context.Context, templateID, uid int, initiate bool) (*PAMITSMTemplate, error) {
	var result PAMITSMTemplate
	err := callPAMITSM(ctx, "template", map[string]any{"template_id": templateID, "requester_uid": uid, "require_initiate": initiate}, &result)
	if err != nil {
		var remote *pamITSMRemoteError
		if errors.As(err, &remote) && remote.Status == http.StatusForbidden && remote.Code == "request_rejected" {
			return nil, ErrPAMTemplateDenied
		}
		return nil, err
	}
	if result.TemplateID != templateID || result.NodeID <= 0 || len(result.TemplateRevision) != 64 {
		return nil, ErrPAMScopeChanged
	}
	return &result, nil
}

func ListPAMITSMTemplates(ctx context.Context, uid int, search string) ([]PAMITSMTemplate, error) {
	result := []PAMITSMTemplate{}
	err := callPAMITSM(ctx, "templates", map[string]any{"requester_uid": uid, "search": search}, &result)
	return result, err
}

func GetPAMITSMTemplate(ctx context.Context, templateID, uid int, initiate bool) (*PAMITSMTemplate, error) {
	return describePAMITSMTemplate(ctx, templateID, uid, initiate)
}
