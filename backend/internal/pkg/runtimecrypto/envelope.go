package runtimecrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	EnvelopePrefix  = "prx"
	EnvelopeVersion = "v1"
	AES256KeySize   = 32
)

var (
	ErrInvalidEnvelope = errors.New("invalid proxy runtime ciphertext envelope")
	ErrUnknownKey      = errors.New("unknown proxy runtime encryption key")
	ErrInvalidPurpose  = errors.New("invalid proxy runtime encryption purpose")
)

// Keyring encrypts with ActiveKeyID and can decrypt older key IDs during
// rotation. Callers must supply keys from a durable secret provider; keys are
// never generated or persisted by this package.
type Keyring struct {
	ActiveKeyID string
	Keys        map[string][]byte
	randReader  io.Reader
}

func NewKeyring(activeKeyID string, keys map[string][]byte) (*Keyring, error) {
	activeKeyID = strings.TrimSpace(activeKeyID)
	if !validToken(activeKeyID) {
		return nil, fmt.Errorf("active key id: %w", ErrInvalidEnvelope)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("empty keyring: %w", ErrUnknownKey)
	}
	cloned := make(map[string][]byte, len(keys))
	for id, key := range keys {
		if !validToken(id) {
			return nil, fmt.Errorf("key id %q: %w", id, ErrInvalidEnvelope)
		}
		if len(key) != AES256KeySize {
			return nil, fmt.Errorf("key %q must be %d bytes", id, AES256KeySize)
		}
		cloned[id] = append([]byte(nil), key...)
	}
	if _, ok := cloned[activeKeyID]; !ok {
		return nil, fmt.Errorf("active key %q: %w", activeKeyID, ErrUnknownKey)
	}
	return &Keyring{ActiveKeyID: activeKeyID, Keys: cloned, randReader: rand.Reader}, nil
}

func (k *Keyring) Encrypt(purpose string, plaintext []byte) (string, error) {
	if !validPurpose(purpose) {
		return "", ErrInvalidPurpose
	}
	key, ok := k.Keys[k.ActiveKeyID]
	if !ok {
		return "", ErrUnknownKey
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	reader := k.randReader
	if reader == nil {
		reader = rand.Reader
	}
	if _, err := io.ReadFull(reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	aad := associatedData(k.ActiveKeyID, purpose)
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	payload := append(nonce, sealed...)
	return strings.Join([]string{EnvelopePrefix, EnvelopeVersion, k.ActiveKeyID, purpose, base64.RawURLEncoding.EncodeToString(payload)}, ":"), nil
}

func (k *Keyring) Decrypt(expectedPurpose, envelope string) ([]byte, error) {
	if !validPurpose(expectedPurpose) {
		return nil, ErrInvalidPurpose
	}
	parts := strings.Split(envelope, ":")
	if len(parts) != 5 || parts[0] != EnvelopePrefix || parts[1] != EnvelopeVersion || !validToken(parts[2]) || !validPurpose(parts[3]) {
		return nil, ErrInvalidEnvelope
	}
	if parts[3] != expectedPurpose {
		return nil, ErrInvalidPurpose
	}
	key, ok := k.Keys[parts[2]]
	if !ok {
		return nil, ErrUnknownKey
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(payload) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrInvalidEnvelope
	}
	nonce, ciphertext := payload[:gcm.NonceSize()], payload[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, associatedData(parts[2], parts[3]))
	if err != nil {
		return nil, fmt.Errorf("authenticate runtime ciphertext: %w", err)
	}
	return plain, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	return gcm, nil
}

func associatedData(keyID, purpose string) []byte {
	return []byte(EnvelopePrefix + ":" + EnvelopeVersion + ":" + keyID + ":" + purpose)
}

func validPurpose(value string) bool {
	return value == "source" || value == "config"
}

func validToken(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	const allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	for _, r := range value {
		if !strings.ContainsRune(allowed, r) {
			return false
		}
	}
	return true
}
