package acl

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"

	"github.com/veops/oneterm/pkg/config"
)

const (
	PAMMFAAudience = "oneops:oneterm:pam"
	PAMMFAIssuer   = "oneops:identity"
	PAMMFARetrieve = "oneterm_pam_retrieve"
	PAMMFAPolicy   = "oneterm_pam_policy"
	PAMMFARotate   = "oneterm_pam_rotate"
)

var identityClient = resty.New().SetTimeout(5 * time.Second).SetRedirectPolicy(resty.NoRedirectPolicy())

type MFAIntrospectRequest struct {
	MfaToken string `json:"mfa_token"`
}

type MFAIntrospectResponse struct {
	Active      bool   `json:"active"`
	Version     int    `json:"ver"`
	ACLUID      int    `json:"acl_uid"`
	SubjectType string `json:"subject_type"`
	Scope       string `json:"scope"`
	Audience    string `json:"aud"`
	Issuer      string `json:"iss"`
	Binding     string `json:"binding"`
	Exp         int64  `json:"exp"`
	AuthTime    int64  `json:"auth_time"`
}

func identityBinding(kind, value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(kind + ":" + value))
	return hex.EncodeToString(sum[:])
}

func (m MFAIntrospectResponse) validFor(session *Session, scope string, now int64) bool {
	return session != nil && session.Uid > 0 && session.authBinding != "" && scope != "" &&
		m.Active && m.Version == 1 && m.ACLUID == session.Uid && m.SubjectType == "user" &&
		m.Audience == PAMMFAAudience && m.Issuer == PAMMFAIssuer && m.Scope == scope &&
		m.AuthTime > 0 && m.AuthTime <= now && m.AuthTime >= now-300 && m.Exp > now && m.Exp <= m.AuthTime+300 &&
		hmac.Equal([]byte(m.Binding), []byte(session.authBinding))
}

func identityEndpoint(suffix string) (string, error) {
	endpoint, err := url.Parse(config.Cfg.Auth.Acl.Url)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
		return "", errors.New("invalid identity service URL")
	}
	path := strings.TrimSuffix(endpoint.Path, "/")
	if !strings.HasSuffix(path, "/v1") {
		return "", errors.New("invalid identity service API path")
	}
	endpoint.Path = strings.TrimSuffix(path, "/v1") + "/common-setting/v1/" + suffix
	endpoint.RawPath, endpoint.RawQuery, endpoint.Fragment = "", "", ""
	return endpoint.String(), nil
}

func VerifyMFAToken(ctx context.Context, session *Session, token, scope string) bool {
	if session == nil || session.Uid <= 0 || scope == "" || len(token) > 8192 {
		return false
	}
	subject, err := getPAMKeySubject(ctx, session.Uid, true)
	if err != nil || subject.Blocked {
		return false
	}
	// Only the authenticated identity service can exempt the current user from MFA.
	if subject.MFARequired != nil && !*subject.MFARequired {
		return true
	}
	if session.authBinding == "" || token == "" {
		return false
	}
	endpoint, err := identityEndpoint("mfa/introspect")
	if err != nil {
		return false
	}
	var result MFAIntrospectResponse
	response, err := identityClient.R().SetContext(ctx).SetBody(MFAIntrospectRequest{MfaToken: token}).
		SetResult(&result).Post(endpoint)
	return err == nil && response.StatusCode() == 200 && result.validFor(session, scope, time.Now().Unix())
}
