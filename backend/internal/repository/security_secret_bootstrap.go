package repository

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/securitysecret"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/runtimecrypto"
)

const (
	securitySecretKeyJWT              = "jwt_secret"
	securitySecretKeyProxyRuntimeV1   = "proxy_runtime_encryption_key_v1"
	proxyRuntimeActiveEncryptionKeyID = "db-v1"
	securitySecretReadRetryMax        = 5
	securitySecretReadRetryWait       = 10 * time.Millisecond
)

var readRandomBytes = rand.Read

func ensureBootstrapSecrets(ctx context.Context, client *ent.Client, cfg *config.Config) error {
	if client == nil {
		return fmt.Errorf("nil ent client")
	}
	if cfg == nil {
		return fmt.Errorf("nil config")
	}

	cfg.JWT.Secret = strings.TrimSpace(cfg.JWT.Secret)
	if cfg.JWT.Secret != "" {
		storedSecret, err := createSecuritySecretIfAbsent(ctx, client, securitySecretKeyJWT, cfg.JWT.Secret)
		if err != nil {
			return fmt.Errorf("persist jwt secret: %w", err)
		}
		if storedSecret != cfg.JWT.Secret {
			log.Println("Warning: configured JWT secret mismatches persisted value; using persisted secret for cross-instance consistency.")
		}
		cfg.JWT.Secret = storedSecret
		return nil
	}

	secret, created, err := getOrCreateGeneratedSecuritySecret(ctx, client, securitySecretKeyJWT, 32)
	if err != nil {
		return fmt.Errorf("ensure jwt secret: %w", err)
	}
	cfg.JWT.Secret = secret

	if created {
		log.Println("Warning: JWT secret auto-generated and persisted to database. Consider rotating to a managed secret for production.")
	}
	return nil
}

// LoadProxyRuntimeKeyring returns a durable, rotation-capable keyring for
// native proxy secrets. It intentionally does not reuse the TOTP key: that key
// may be generated per process when unset and therefore cannot protect data
// that must survive restarts or multi-instance deployments.
func LoadProxyRuntimeKeyring(ctx context.Context, client *ent.Client) (*runtimecrypto.Keyring, error) {
	if client == nil {
		return nil, fmt.Errorf("nil ent client")
	}
	secretHex, created, err := getOrCreateGeneratedSecuritySecret(ctx, client, securitySecretKeyProxyRuntimeV1, runtimecrypto.AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("ensure proxy runtime encryption key: %w", err)
	}
	key, err := hex.DecodeString(secretHex)
	if err != nil || len(key) != runtimecrypto.AES256KeySize {
		return nil, fmt.Errorf("stored secret %q must be %d-byte hex", securitySecretKeyProxyRuntimeV1, runtimecrypto.AES256KeySize)
	}
	keyring, err := runtimecrypto.NewKeyring(proxyRuntimeActiveEncryptionKeyID, map[string][]byte{
		proxyRuntimeActiveEncryptionKeyID: key,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize proxy runtime keyring: %w", err)
	}
	if created {
		log.Println("Native proxy runtime encryption key generated and persisted to database.")
	}
	return keyring, nil
}

func getOrCreateGeneratedSecuritySecret(ctx context.Context, client *ent.Client, key string, byteLength int) (string, bool, error) {
	existing, err := client.SecuritySecret.Query().Where(securitysecret.KeyEQ(key)).Only(ctx)
	if err == nil {
		value := strings.TrimSpace(existing.Value)
		if len([]byte(value)) < 32 {
			return "", false, fmt.Errorf("stored secret %q must be at least 32 bytes", key)
		}
		return value, false, nil
	}
	if !ent.IsNotFound(err) {
		return "", false, err
	}

	generated, err := generateHexSecret(byteLength)
	if err != nil {
		return "", false, err
	}

	if err := client.SecuritySecret.Create().
		SetKey(key).
		SetValue(generated).
		OnConflictColumns(securitysecret.FieldKey).
		DoNothing().
		Exec(ctx); err != nil {
		if !isSQLNoRowsError(err) {
			return "", false, err
		}
	}

	stored, err := querySecuritySecretWithRetry(ctx, client, key)
	if err != nil {
		return "", false, err
	}
	value := strings.TrimSpace(stored.Value)
	if len([]byte(value)) < 32 {
		return "", false, fmt.Errorf("stored secret %q must be at least 32 bytes", key)
	}
	return value, value == generated, nil
}

func createSecuritySecretIfAbsent(ctx context.Context, client *ent.Client, key, value string) (string, error) {
	value = strings.TrimSpace(value)
	if len([]byte(value)) < 32 {
		return "", fmt.Errorf("secret %q must be at least 32 bytes", key)
	}

	if err := client.SecuritySecret.Create().
		SetKey(key).
		SetValue(value).
		OnConflictColumns(securitysecret.FieldKey).
		DoNothing().
		Exec(ctx); err != nil {
		if !isSQLNoRowsError(err) {
			return "", err
		}
	}

	stored, err := querySecuritySecretWithRetry(ctx, client, key)
	if err != nil {
		return "", err
	}
	storedValue := strings.TrimSpace(stored.Value)
	if len([]byte(storedValue)) < 32 {
		return "", fmt.Errorf("stored secret %q must be at least 32 bytes", key)
	}
	return storedValue, nil
}

func querySecuritySecretWithRetry(ctx context.Context, client *ent.Client, key string) (*ent.SecuritySecret, error) {
	var lastErr error
	for attempt := 0; attempt <= securitySecretReadRetryMax; attempt++ {
		stored, err := client.SecuritySecret.Query().Where(securitysecret.KeyEQ(key)).Only(ctx)
		if err == nil {
			return stored, nil
		}
		if !isSecretNotFoundError(err) {
			return nil, err
		}
		lastErr = err
		if attempt == securitySecretReadRetryMax {
			break
		}

		timer := time.NewTimer(securitySecretReadRetryWait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}

func isSecretNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	return ent.IsNotFound(err) || isSQLNoRowsError(err)
}

func isSQLNoRowsError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), "no rows in result set")
}

func generateHexSecret(byteLength int) (string, error) {
	if byteLength <= 0 {
		byteLength = 32
	}
	buf := make([]byte, byteLength)
	if _, err := readRandomBytes(buf); err != nil {
		return "", fmt.Errorf("generate random secret: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
