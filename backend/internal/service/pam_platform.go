package service

import (
	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/model"
)

type PAMPlatformDefinition struct {
	ID                 string   `json:"id"`
	Protocol           string   `json:"protocol,omitempty"`
	LocalAuthorityOnly bool     `json:"local_authority_only"`
	PasswordOnly       bool     `json:"password_only"`
	RequiresQualifier  bool     `json:"requires_qualifier"`
	Operations         []string `json:"operations"`
}

// Operations are enabled only when their executor is registered and verified.
var pamPlatformDefinitions = []PAMPlatformDefinition{
	{ID: "manual", Operations: []string{}},
	{ID: "linux_local", Protocol: "ssh", LocalAuthorityOnly: true, Operations: []string{acl.VerifySecret, acl.RotateSecret, acl.RecoverSecret}},
	{ID: "mysql", Protocol: "mysql", PasswordOnly: true, RequiresQualifier: true, Operations: []string{acl.VerifySecret, acl.RotateSecret, acl.RecoverSecret}},
}

func PAMPlatforms() []PAMPlatformDefinition {
	result := make([]PAMPlatformDefinition, len(pamPlatformDefinitions))
	copy(result, pamPlatformDefinitions)
	for index := range result {
		result[index].Operations = append([]string{}, result[index].Operations...)
	}
	return result
}

func PAMPlatform(id string) (PAMPlatformDefinition, bool) {
	for _, platform := range pamPlatformDefinitions {
		if platform.ID == id {
			return platform, true
		}
	}
	return PAMPlatformDefinition{}, false
}

func platformSupportsBinding(platform PAMPlatformDefinition, authority string, method int, qualifier string, protocols map[string]bool) bool {
	if platform.Protocol != "" && !protocols[platform.Protocol] {
		return false
	}
	if platform.LocalAuthorityOnly && authority != model.PAMAuthorityAsset {
		return false
	}
	if platform.PasswordOnly && method != model.AUTHMETHOD_PASSWORD {
		return false
	}
	return platform.RequiresQualifier == (qualifier != "")
}
