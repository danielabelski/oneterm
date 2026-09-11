package acl

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const PAMServicePurpose = "oneops:pam:itsm:v1"

func pamServiceKey(secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(PAMServicePurpose))
	return mac.Sum(nil)
}

func PAMServiceSignature(secret, sender, method, path string, body []byte, timestamp, nonce string) string {
	digest := sha256.Sum256(body)
	message := strings.Join([]string{PAMServicePurpose, sender, method, path, timestamp, nonce, hex.EncodeToString(digest[:])}, "\n")
	mac := hmac.New(sha256.New, pamServiceKey(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func SignPAMServiceRequest(secret string, request *http.Request, body []byte) (string, error) {
	if secret == "" || request.Method != http.MethodPost || request.URL.RawQuery != "" ||
		!strings.HasPrefix(request.URL.Path, "/api/itsm/v1/pam/") || request.URL.RawPath != "" {
		return "", fmt.Errorf("invalid PAM service request")
	}
	if len(body) > 65536 {
		return "", fmt.Errorf("PAM service payload is too large")
	}
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(random)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	request.Header.Set("X-PAM-Service", "oneterm")
	request.Header.Set("X-PAM-Timestamp", timestamp)
	request.Header.Set("X-PAM-Nonce", nonce)
	request.Header.Set("X-PAM-Signature", PAMServiceSignature(secret, "oneterm", request.Method, request.URL.Path, body, timestamp, nonce))
	return nonce, nil
}

func PAMServiceResponseSignature(secret, nonce string, status int, body []byte) string {
	digest := sha256.Sum256(body)
	message := strings.Join([]string{PAMServicePurpose + ":response", nonce, strconv.Itoa(status), hex.EncodeToString(digest[:])}, "\n")
	mac := hmac.New(sha256.New, pamServiceKey(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func VerifyPAMServiceResponse(secret, nonce string, response *http.Response, body []byte) bool {
	if secret == "" || nonce == "" || response == nil {
		return false
	}
	actual, err := hex.DecodeString(response.Header.Get("X-PAM-Response-Signature"))
	if err != nil || len(actual) != sha256.Size {
		return false
	}
	expected, _ := hex.DecodeString(PAMServiceResponseSignature(secret, nonce, response.StatusCode, body))
	return hmac.Equal(actual, expected)
}
