package secret

import (
	"encoding/json"
	"errors"
)

const (
	Password      = "password"
	SSHPrivateKey = "ssh_private_key"
)

var ErrMaterial = errors.New("credential material is invalid")

// Material cannot leak through ordinary JSON responses or structured logging.
type Material struct {
	kind       string
	password   string
	privateKey string
	passphrase string
}

type materialPayload struct {
	Kind       string `json:"kind"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

func NewPassword(value string) Material { return Material{kind: Password, password: value} }
func NewSSHKey(key, phrase string) Material {
	return Material{kind: SSHPrivateKey, privateKey: key, passphrase: phrase}
}
func (m Material) Kind() string                 { return m.kind }
func (m Material) PasswordValue() string        { return m.password }
func (m Material) PrivateKeyValue() string      { return m.privateKey }
func (m Material) PassphraseValue() string      { return m.passphrase }
func (m Material) String() string               { return "credential material [redacted]" }
func (m Material) GoString() string             { return m.String() }
func (m Material) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

func (m Material) EncodeForEncryption() ([]byte, error) {
	if m.kind != Password && m.kind != SSHPrivateKey {
		return nil, ErrMaterial
	}
	data, err := json.Marshal(materialPayload{Kind: m.kind, Password: m.password, PrivateKey: m.privateKey, Passphrase: m.passphrase})
	if len(data) > MaxMaterialSize {
		return nil, ErrTooLarge
	}
	return data, err
}

func DecodeMaterial(data []byte) (Material, error) {
	var payload materialPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return Material{}, ErrMaterial
	}
	switch payload.Kind {
	case Password:
		if payload.PrivateKey != "" || payload.Passphrase != "" {
			return Material{}, ErrMaterial
		}
		return NewPassword(payload.Password), nil
	case SSHPrivateKey:
		if payload.Password != "" {
			return Material{}, ErrMaterial
		}
		return NewSSHKey(payload.PrivateKey, payload.Passphrase), nil
	default:
		return Material{}, ErrMaterial
	}
}
