// Package secret provides object-bound, versioned encryption without application or database dependencies.
package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const (
	Prefix          = "oneterm-secret:v1:"
	MaxMaterialSize = 1 << 20
	maxPlaintext    = MaxMaterialSize
)

var (
	ErrKey        = errors.New("secret key is unavailable or invalid")
	ErrContext    = errors.New("secret context is required")
	ErrCiphertext = errors.New("secret ciphertext is invalid")
	ErrTooLarge   = errors.New("secret exceeds the size limit")
)

type envelope struct {
	Version    int    `json:"v"`
	KeyID      string `json:"k"`
	Nonce      []byte `json:"n"`
	Ciphertext []byte `json:"c"`
}

// Codec is immutable after construction and safe for concurrent use.
type Codec struct {
	active string
	keys   map[string][]byte
}

func New(active string, keys map[string][]byte) (*Codec, error) {
	if active == "" || len(keys[active]) != 32 {
		return nil, ErrKey
	}
	cloned := make(map[string][]byte, len(keys))
	for id, key := range keys {
		if id == "" || len(key) != 32 {
			return nil, ErrKey
		}
		cloned[id] = bytes.Clone(key)
	}
	return &Codec{active: active, keys: cloned}, nil
}

func (c *Codec) aead(id string) (cipher.AEAD, error) {
	key, ok := c.keys[id]
	if !ok {
		return nil, ErrKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrKey
	}
	return cipher.NewGCM(block)
}

func associatedData(id, context string) []byte {
	data, _ := json.Marshal([]string{"oneterm-secret:v1", id, context})
	return data
}

func (c *Codec) Seal(context string, plaintext []byte) (string, error) {
	if context == "" {
		return "", ErrContext
	}
	if len(plaintext) > maxPlaintext {
		return "", ErrTooLarge
	}
	aead, err := c.aead(c.active)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	data, err := json.Marshal(envelope{
		Version: 1, KeyID: c.active, Nonce: nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, associatedData(c.active, context)),
	})
	if err != nil {
		return "", err
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func (c *Codec) Open(context, value string) ([]byte, error) {
	if context == "" {
		return nil, ErrContext
	}
	if !strings.HasPrefix(value, Prefix) || len(value) > 2*maxPlaintext+1024 {
		return nil, ErrCiphertext
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, Prefix))
	if err != nil {
		return nil, ErrCiphertext
	}
	var e envelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&e); err != nil || e.Version != 1 {
		return nil, ErrCiphertext
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return nil, ErrCiphertext
	}
	aead, err := c.aead(e.KeyID)
	if err != nil {
		return nil, err
	}
	if len(e.Nonce) != aead.NonceSize() || len(e.Ciphertext) < aead.Overhead() {
		return nil, ErrCiphertext
	}
	plaintext, err := aead.Open(nil, e.Nonce, e.Ciphertext, associatedData(e.KeyID, context))
	if err != nil {
		return nil, ErrCiphertext
	}
	return plaintext, nil
}

// OpenLegacyCBC is only for existing records. It never treats undecodable input as plaintext.
func OpenLegacyCBC(key, iv []byte, encoded string) ([]byte, error) {
	if len(encoded) > 2*maxPlaintext {
		return nil, ErrTooLarge
	}
	if encoded == "" {
		return []byte{}, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil || len(iv) != aes.BlockSize {
		return nil, ErrKey
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, ErrCiphertext
	}
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(data, data)
	padding := int(data[len(data)-1])
	if padding < 1 || padding > aes.BlockSize || padding > len(data) {
		return nil, ErrCiphertext
	}
	for _, b := range data[len(data)-padding:] {
		if int(b) != padding {
			return nil, ErrCiphertext
		}
	}
	return data[:len(data)-padding], nil
}
