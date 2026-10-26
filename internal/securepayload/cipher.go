// Package securepayload encrypts application data before it is stored in PostgreSQL.
package securepayload

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const KeyBytes = 32

const envelopeMarker = "ubuntu-fleet-manager:aes-256-gcm:v1"

type Cipher struct {
	aead cipher.AEAD
}

type envelope struct {
	Marker     string `json:"ufm_encrypted_payload"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func New(key []byte) (*Cipher, error) {
	if len(key) != KeyBytes {
		return nil, fmt.Errorf("application encryption key must contain exactly %d bytes", KeyBytes)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize application encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize application authenticated encryption: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

func LoadKeyFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("application encryption key path must be absolute")
	}
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect application encryption key file: %w", err)
	}
	if !linkInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("application encryption key must be a regular file, not a symlink")
	}
	if !validKeyFileMode(linkInfo.Mode().Perm()) {
		return nil, fmt.Errorf("application encryption key file permissions are too broad; set mode 0400 or 0600")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open application encryption key file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect application encryption key file: %w", err)
	}
	if !info.Mode().IsRegular() || !validKeyFileMode(info.Mode().Perm()) {
		return nil, fmt.Errorf("application encryption key file must be regular and private")
	}
	key, err := io.ReadAll(io.LimitReader(file, KeyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read application encryption key file: %w", err)
	}
	if len(key) != KeyBytes {
		return nil, fmt.Errorf("application encryption key file must contain exactly %d bytes", KeyBytes)
	}
	return key, nil
}

func validKeyFileMode(mode os.FileMode) bool {
	return mode == 0o400 || mode == 0o600
}

func (c *Cipher) Seal(plaintext, associatedData []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, fmt.Errorf("application encryption is unavailable")
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate application encryption nonce: %w", err)
	}
	ciphertext := c.aead.Seal(nil, nonce, plaintext, associatedData)
	encoded, err := json.Marshal(envelope{
		Marker:     envelopeMarker,
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return nil, fmt.Errorf("encode encrypted application payload: %w", err)
	}
	return encoded, nil
}

func (c *Cipher) Open(sealed, associatedData []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, fmt.Errorf("application encryption is unavailable")
	}
	var encoded envelope
	decoder := json.NewDecoder(bytes.NewReader(sealed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&encoded); err != nil {
		return nil, fmt.Errorf("decode encrypted application payload: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("encrypted application payload must contain one JSON object")
	}
	if encoded.Marker != envelopeMarker {
		return nil, fmt.Errorf("encrypted application payload has an unsupported version")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(encoded.Nonce)
	if err != nil || len(nonce) != c.aead.NonceSize() {
		return nil, fmt.Errorf("encrypted application payload nonce is invalid")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(encoded.Ciphertext)
	if err != nil || len(ciphertext) < c.aead.Overhead() {
		return nil, fmt.Errorf("encrypted application payload ciphertext is invalid")
	}
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("authenticate encrypted application payload: %w", err)
	}
	return plaintext, nil
}

// OpenIfSealed returns raw JSON unchanged for jobs created before payload
// encryption was enabled. New writes always use Seal.
func (c *Cipher) OpenIfSealed(value, associatedData []byte) ([]byte, bool, error) {
	var marker map[string]json.RawMessage
	if err := json.Unmarshal(value, &marker); err != nil {
		return nil, false, fmt.Errorf("decode application payload: %w", err)
	}
	if marker == nil {
		return nil, false, fmt.Errorf("application payload must be a JSON object")
	}
	rawMarker, exists := marker["ufm_encrypted_payload"]
	if !exists {
		return append([]byte(nil), value...), false, nil
	}
	var version string
	if err := json.Unmarshal(rawMarker, &version); err != nil || version != envelopeMarker {
		return nil, true, fmt.Errorf("encrypted application payload version is invalid")
	}
	plaintext, err := c.Open(value, associatedData)
	return plaintext, true, err
}
