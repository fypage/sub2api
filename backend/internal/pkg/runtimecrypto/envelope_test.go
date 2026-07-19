package runtimecrypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func key(fill byte) []byte { return bytes.Repeat([]byte{fill}, AES256KeySize) }

func TestEnvelopeRoundTripAndPurposeIsolation(t *testing.T) {
	kr, err := NewKeyring("k1", map[string][]byte{"k1": key(1)})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := kr.Encrypt("source", []byte(`vless://secret@example.com`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ciphertext, "prx:v1:k1:source:") {
		t.Fatalf("unexpected envelope: %s", ciphertext)
	}
	plain, err := kr.Decrypt("source", ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != `vless://secret@example.com` {
		t.Fatalf("unexpected plaintext: %q", plain)
	}
	if _, err := kr.Decrypt("config", ciphertext); !errors.Is(err, ErrInvalidPurpose) {
		t.Fatalf("expected purpose isolation, got %v", err)
	}
}

func TestEnvelopeNonceRandomness(t *testing.T) {
	kr, _ := NewKeyring("k1", map[string][]byte{"k1": key(2)})
	a, err := kr.Encrypt("config", []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := kr.Encrypt("config", []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("ciphertexts must differ")
	}
}

func TestEnvelopeRotationDecryptsOldAndEncryptsNew(t *testing.T) {
	oldRing, _ := NewKeyring("old", map[string][]byte{"old": key(3)})
	oldCiphertext, err := oldRing.Encrypt("source", []byte("legacy"))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewKeyring("new", map[string][]byte{"old": key(3), "new": key(4)})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := rotated.Decrypt("source", oldCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "legacy" {
		t.Fatalf("unexpected old plaintext: %q", plain)
	}
	newCiphertext, err := rotated.Encrypt("source", []byte("current"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(newCiphertext, "prx:v1:new:source:") {
		t.Fatalf("new key not active: %s", newCiphertext)
	}
}

func TestEnvelopeRejectsTamperingUnknownKeyAndMalformedInput(t *testing.T) {
	kr, _ := NewKeyring("k1", map[string][]byte{"k1": key(5)})
	ciphertext, _ := kr.Encrypt("source", []byte("secret"))
	parts := strings.Split(ciphertext, ":")
	payload, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatal(err)
	}
	payload[len(payload)-1] ^= 1
	parts[4] = base64.RawURLEncoding.EncodeToString(payload)
	tampered := strings.Join(parts, ":")
	if _, err := kr.Decrypt("source", tampered); err == nil {
		t.Fatal("tampering must fail")
	}
	unknown := strings.Replace(ciphertext, ":k1:", ":k2:", 1)
	if _, err := kr.Decrypt("source", unknown); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("expected unknown key, got %v", err)
	}
	for _, value := range []string{"", "prx:v1", "prx:v2:k1:source:abc", "prx:v1:bad:key:source:abc"} {
		if _, err := kr.Decrypt("source", value); !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("%q: %v", value, err)
		}
	}
}

func TestNewKeyringValidationAndDefensiveCopy(t *testing.T) {
	if _, err := NewKeyring("missing", map[string][]byte{"k1": key(1)}); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("expected unknown active key, got %v", err)
	}
	if _, err := NewKeyring("k1", map[string][]byte{"k1": []byte("short")}); err == nil {
		t.Fatal("short key must fail")
	}
	original := key(9)
	kr, err := NewKeyring("k1", map[string][]byte{"k1": original})
	if err != nil {
		t.Fatal(err)
	}
	original[0] = 0
	ciphertext, err := kr.Encrypt("config", []byte("copy"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Decrypt("config", ciphertext); err != nil {
		t.Fatal(err)
	}
}
