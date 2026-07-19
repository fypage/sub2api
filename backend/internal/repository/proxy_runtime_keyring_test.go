package repository

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/Wei-Shaw/sub2api/ent/securitysecret"
	"github.com/stretchr/testify/require"
)

func TestLoadProxyRuntimeKeyringPersistsAcrossInstances(t *testing.T) {
	client := newSecuritySecretTestClient(t)
	first, err := LoadProxyRuntimeKeyring(context.Background(), client)
	require.NoError(t, err)

	ciphertext, err := first.Encrypt("source", []byte("vless://secret@example.test"))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(ciphertext, "prx:v1:db-v1:source:"))

	second, err := LoadProxyRuntimeKeyring(context.Background(), client)
	require.NoError(t, err)
	plaintext, err := second.Decrypt("source", ciphertext)
	require.NoError(t, err)
	require.Equal(t, "vless://secret@example.test", string(plaintext))

	stored, err := client.SecuritySecret.Query().Where(securitysecret.KeyEQ(securitySecretKeyProxyRuntimeV1)).Only(context.Background())
	require.NoError(t, err)
	require.Len(t, stored.Value, 64)
	require.NotContains(t, stored.Value, "vless://")
}

func TestLoadProxyRuntimeKeyringConcurrentInstancesShareKey(t *testing.T) {
	client := newSecuritySecretTestClient(t)
	const count = 8
	keyrings := make([]interface {
		Encrypt(string, []byte) (string, error)
		Decrypt(string, string) ([]byte, error)
	}, count)
	errs := make([]error, count)

	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			keyrings[index], errs[index] = LoadProxyRuntimeKeyring(context.Background(), client)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}

	ciphertext, err := keyrings[0].Encrypt("config", []byte(`{"type":"vless"}`))
	require.NoError(t, err)
	for _, keyring := range keyrings[1:] {
		plaintext, err := keyring.Decrypt("config", ciphertext)
		require.NoError(t, err)
		require.JSONEq(t, `{"type":"vless"}`, string(plaintext))
	}

	countStored, err := client.SecuritySecret.Query().Where(securitysecret.KeyEQ(securitySecretKeyProxyRuntimeV1)).Count(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, countStored)
}

func TestLoadProxyRuntimeKeyringRejectsInvalidStoredKey(t *testing.T) {
	client := newSecuritySecretTestClient(t)
	_, err := client.SecuritySecret.Create().
		SetKey(securitySecretKeyProxyRuntimeV1).
		SetValue(strings.Repeat("z", 64)).
		Save(context.Background())
	require.NoError(t, err)

	_, err = LoadProxyRuntimeKeyring(context.Background(), client)
	require.Error(t, err)
	require.Contains(t, err.Error(), "32-byte hex")
}

func TestLoadProxyRuntimeKeyringSeparatesPurposes(t *testing.T) {
	client := newSecuritySecretTestClient(t)
	keyring, err := LoadProxyRuntimeKeyring(context.Background(), client)
	require.NoError(t, err)

	ciphertext, err := keyring.Encrypt("source", []byte("secret"))
	require.NoError(t, err)
	_, err = keyring.Decrypt("config", ciphertext)
	require.Error(t, err)
}
