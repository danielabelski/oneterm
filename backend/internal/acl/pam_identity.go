package acl

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/veops/oneterm/pkg/config"
	"github.com/veops/oneterm/pkg/remote"
)

const PAMKeyAudience = "oneops:oneterm:pam:application"

var (
	ErrPAMKeyEvidence      = errors.New("application identity could not be verified")
	ErrIdentityUnavailable = errors.New("identity service is unavailable")
	evidenceNoncePattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{20,128}$`)
	evidenceHashPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type PAMKeyIdentity struct {
	Active         bool   `json:"active"`
	Version        int    `json:"ver"`
	Issuer         string `json:"iss"`
	Audience       string `json:"aud"`
	ACLUID         int    `json:"acl_uid"`
	SubjectType    string `json:"subject_type"`
	TokenUse       string `json:"token_use"`
	KeyFingerprint string `json:"key_fingerprint"`
	Method         string `json:"method"`
	Path           string `json:"path"`
	RequestSHA256  string `json:"request_sha256"`
	IssuedAt       int64  `json:"iat"`
	ExpiresAt      int64  `json:"exp"`
	ID             string `json:"jti"`
}

func (e *PAMKeyIdentity) validFor(method, path string, body []byte, now int64) bool {
	if e == nil {
		return false
	}
	digest := sha256.Sum256(body)
	return e.Active && e.Version == 1 && e.Issuer == PAMMFAIssuer && e.Audience == PAMKeyAudience &&
		e.ACLUID > 0 && e.SubjectType == "key" && e.TokenUse == "pam_key_evidence" &&
		e.IssuedAt > 0 && e.IssuedAt <= now && e.IssuedAt >= now-60 && e.ExpiresAt > now && e.ExpiresAt <= e.IssuedAt+60 &&
		e.Method == method && e.Path == path && method == "POST" && evidenceNoncePattern.MatchString(e.ID) &&
		evidenceHashPattern.MatchString(e.KeyFingerprint) &&
		hmac.Equal([]byte(e.RequestSHA256), []byte(hex.EncodeToString(digest[:])))
}

// VerifyPAMKey proves possession of an active ACL key; the application grant is checked separately.
func VerifyPAMKey(ctx context.Context, token, method, path string, body []byte) (*PAMKeyIdentity, error) {
	if token == "" || len(token) > 8192 {
		return nil, ErrPAMKeyEvidence
	}
	endpoint, err := identityEndpoint("pam/key-evidence/introspect")
	if err != nil {
		return nil, ErrIdentityUnavailable
	}
	var identity PAMKeyIdentity
	response, err := identityClient.R().SetContext(ctx).
		SetBody(map[string]string{"evidence_token": token}).SetResult(&identity).Post(endpoint)
	if err != nil || response.StatusCode() != 200 {
		return nil, ErrIdentityUnavailable
	}
	if !identity.validFor(method, path, body, time.Now().Unix()) {
		return nil, ErrPAMKeyEvidence
	}
	return &identity, nil
}

type PAMKeySubject struct {
	UID         int    `json:"uid"`
	Username    string `json:"username"`
	Nickname    string `json:"nickname"`
	Blocked     bool   `json:"block"`
	MFARequired *bool  `json:"mfa_required,omitempty"`
}

// GetPAMKeySubject reuses the ACL user route without fetching keys or expanding parent roles.
func GetPAMKeySubject(ctx context.Context, uid int) (*PAMKeySubject, error) {
	return getPAMKeySubject(ctx, uid, false)
}

func getPAMKeySubject(ctx context.Context, uid int, includeMFAPolicy bool) (*PAMKeySubject, error) {
	if uid <= 0 {
		return nil, ErrPAMKeyEvidence
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	token, err := remote.GetAclToken(ctx)
	if err != nil {
		return nil, ErrIdentityUnavailable
	}
	var result struct {
		User PAMKeySubject `json:"user"`
	}
	endpoint := fmt.Sprintf("%s/acl/users/%d", strings.TrimRight(config.Cfg.Auth.Acl.Url, "/"), uid)
	request := identityClient.R().SetContext(ctx).SetHeader("App-Access-Token", token).SetResult(&result)
	if includeMFAPolicy {
		request.SetQueryParam("include_mfa_policy", "1")
	}
	response, err := request.Get(endpoint)
	if err != nil || (response.StatusCode() != 200 && response.StatusCode() != 404) {
		return nil, ErrIdentityUnavailable
	}
	if response.StatusCode() == 404 || result.User.UID != uid {
		return nil, ErrPAMKeyEvidence
	}
	return &result.User, nil
}
