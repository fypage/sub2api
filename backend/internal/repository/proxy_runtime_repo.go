package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lib/pq"
)

var (
	ErrProxyRuntimeInvalid  = errors.New("invalid native proxy runtime input")
	ErrProxyRuntimeConflict = errors.New("native proxy runtime conflicts with an existing node or listener")
)

const (
	maxProxyRuntimeBatchItems      = 512
	maxProxyRuntimeCiphertext      = 4 << 20
	maxProxyRuntimeBatchCiphertext = 16 << 20
)

var runtimeFingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type ProxyRuntimeSourceInput struct {
	Name                   string
	SourceType             string
	SourceSecretEncrypted  string
	EncryptionVersion      int16
	RefreshIntervalMinutes int
	ETag                   string
	LastModified           string
}

type ProxyRuntimeCreateInput struct {
	Name                      string
	Visibility                string
	NormalizedConfigEncrypted string
	EncryptionVersion         int16
	NodeFingerprint           string
	SourceNodeKey             string
	ListenHost                string
	ListenPort                int
	ListenUsername            string
	ListenPassword            string
	FallbackMode              string
	BackupProxyID             *int64
}

type ProxyRuntimeBatchInput struct {
	OwnerUserID *int64
	Source      *ProxyRuntimeSourceInput
	Runtimes    []ProxyRuntimeCreateInput
}

type ProxyRuntimeCreated struct {
	ProxyID   int64
	RuntimeID int64
}

type ProxyRuntimeBatchResult struct {
	SourceID *int64
	Items    []ProxyRuntimeCreated
}

type ProxyRuntimeRepository struct {
	db *sql.DB
}

func NewProxyRuntimeRepository(db *sql.DB) *ProxyRuntimeRepository {
	return &ProxyRuntimeRepository{db: db}
}

func (r *ProxyRuntimeRepository) CreateBatch(ctx context.Context, input ProxyRuntimeBatchInput) (*ProxyRuntimeBatchResult, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("proxy runtime repository database is required")
	}
	if err := validateRuntimeBatch(input); err != nil {
		return nil, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin native proxy runtime transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	result := &ProxyRuntimeBatchResult{Items: make([]ProxyRuntimeCreated, 0, len(input.Runtimes))}
	if input.Source != nil {
		sourceID, err := insertRuntimeSource(ctx, tx, input.OwnerUserID, *input.Source)
		if err != nil {
			return nil, classifyRuntimeWriteError(err)
		}
		result.SourceID = &sourceID
	}
	for _, runtime := range input.Runtimes {
		if runtime.ListenPort == 0 {
			allocatedPort, err := allocateRuntimePortTx(ctx, tx, 21000, 21999)
			if err != nil {
				return nil, classifyRuntimeWriteError(err)
			}
			runtime.ListenPort = allocatedPort
		}
		proxyID, err := insertPendingProxy(ctx, tx, runtime)
		if err != nil {
			return nil, classifyRuntimeWriteError(err)
		}
		runtimeID, err := insertPendingRuntime(ctx, tx, proxyID, result.SourceID, input.OwnerUserID, runtime)
		if err != nil {
			return nil, classifyRuntimeWriteError(err)
		}
		result.Items = append(result.Items, ProxyRuntimeCreated{ProxyID: proxyID, RuntimeID: runtimeID})
	}
	if err := tx.Commit(); err != nil {
		return nil, classifyRuntimeWriteError(err)
	}
	return result, nil
}

func allocateRuntimePortTx(ctx context.Context, tx *sql.Tx, first, last int) (int, error) {
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtext('proxy_runtime_port_allocation'))"); err != nil {
		return 0, fmt.Errorf("lock native proxy runtime port allocation: %w", err)
	}
	var port int
	err := tx.QueryRowContext(ctx, `
SELECT candidate
FROM generate_series($1, $2) AS candidate
WHERE NOT EXISTS (
    SELECT 1 FROM proxy_runtimes
    WHERE deleted_at IS NULL AND listen_host = '127.0.0.1' AND listen_port = candidate
)
ORDER BY candidate LIMIT 1`, first, last).Scan(&port)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrProxyRuntimeConflict
	}
	if err != nil {
		return 0, fmt.Errorf("allocate native proxy runtime port: %w", err)
	}
	return port, nil
}

func insertRuntimeSource(ctx context.Context, tx *sql.Tx, ownerID *int64, source ProxyRuntimeSourceInput) (int64, error) {
	var id int64
	err := tx.QueryRowContext(ctx, `
INSERT INTO proxy_runtime_sources
(owner_user_id, name, source_type, source_secret_encrypted, encryption_version,
 refresh_interval_minutes, etag, last_modified, last_sync_at, last_sync_status)
VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), NULLIF($8, ''), NOW(), 'success')
RETURNING id`, nullableInt64(ownerID), strings.TrimSpace(source.Name), source.SourceType,
		source.SourceSecretEncrypted, source.EncryptionVersion, source.RefreshIntervalMinutes,
		source.ETag, source.LastModified).Scan(&id)
	return id, err
}

func insertPendingProxy(ctx context.Context, tx *sql.Tx, runtime ProxyRuntimeCreateInput) (int64, error) {
	fallback := runtime.FallbackMode
	if fallback == "" {
		fallback = "none"
	}
	var id int64
	err := tx.QueryRowContext(ctx, `
INSERT INTO proxies
(name, protocol, host, port, username, password, status, fallback_mode, backup_proxy_id, expiry_warn_days)
VALUES ($1, 'socks5h', $2, $3, $4, $5, 'disabled', $6, $7, 7)
RETURNING id`, strings.TrimSpace(runtime.Name), runtime.ListenHost, runtime.ListenPort,
		runtime.ListenUsername, runtime.ListenPassword, fallback, nullableInt64(runtime.BackupProxyID)).Scan(&id)
	return id, err
}

func insertPendingRuntime(ctx context.Context, tx *sql.Tx, proxyID int64, sourceID, ownerID *int64, runtime ProxyRuntimeCreateInput) (int64, error) {
	var id int64
	err := tx.QueryRowContext(ctx, `
INSERT INTO proxy_runtimes
(proxy_id, source_id, owner_user_id, visibility, normalized_config_encrypted,
 encryption_version, node_fingerprint, source_node_key, listen_host, listen_port, status, auto_start)
VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9, $10, 'pending', TRUE)
RETURNING id`, proxyID, nullableInt64(sourceID), nullableInt64(ownerID), runtime.Visibility,
		runtime.NormalizedConfigEncrypted, runtime.EncryptionVersion, runtime.NodeFingerprint,
		runtime.SourceNodeKey, runtime.ListenHost, runtime.ListenPort).Scan(&id)
	return id, err
}

func validateRuntimeBatch(input ProxyRuntimeBatchInput) error {
	if len(input.Runtimes) == 0 || len(input.Runtimes) > maxProxyRuntimeBatchItems {
		return ErrProxyRuntimeInvalid
	}
	if input.OwnerUserID != nil && *input.OwnerUserID <= 0 {
		return ErrProxyRuntimeInvalid
	}
	if input.Source != nil && !validRuntimeSource(*input.Source) {
		return ErrProxyRuntimeInvalid
	}
	ports := make(map[string]bool, len(input.Runtimes))
	fingerprints := make(map[string]bool, len(input.Runtimes))
	totalCiphertext := 0
	if input.Source != nil {
		totalCiphertext += len(input.Source.SourceSecretEncrypted)
	}
	for _, runtime := range input.Runtimes {
		if !validRuntimeCreate(runtime) || (runtime.Visibility == "private" && input.OwnerUserID == nil) {
			return ErrProxyRuntimeInvalid
		}
		totalCiphertext += len(runtime.NormalizedConfigEncrypted)
		if totalCiphertext > maxProxyRuntimeBatchCiphertext {
			return ErrProxyRuntimeInvalid
		}
		listener := fmt.Sprintf("%s:%d", runtime.ListenHost, runtime.ListenPort)
		if ports[listener] || fingerprints[runtime.NodeFingerprint] {
			return ErrProxyRuntimeInvalid
		}
		ports[listener] = true
		fingerprints[runtime.NodeFingerprint] = true
	}
	return nil
}

func validRuntimeSource(source ProxyRuntimeSourceInput) bool {
	if strings.TrimSpace(source.Name) == "" || len(source.Name) > 100 || len(source.SourceSecretEncrypted) > maxProxyRuntimeCiphertext || !validEncryptedPurpose(source.SourceSecretEncrypted, "source") || source.EncryptionVersion <= 0 || source.RefreshIntervalMinutes < 0 {
		return false
	}
	switch source.SourceType {
	case "xray_link", "singbox_json", "singbox_subscription":
		return true
	default:
		return false
	}
}

func validRuntimeCreate(runtime ProxyRuntimeCreateInput) bool {
	name := strings.TrimSpace(runtime.Name)
	if name == "" || len(name) > 100 || len(runtime.NormalizedConfigEncrypted) > maxProxyRuntimeCiphertext || !validEncryptedPurpose(runtime.NormalizedConfigEncrypted, "config") || runtime.EncryptionVersion <= 0 || !runtimeFingerprintPattern.MatchString(runtime.NodeFingerprint) || (runtime.SourceNodeKey != "" && !runtimeFingerprintPattern.MatchString(runtime.SourceNodeKey)) {
		return false
	}
	if runtime.ListenHost != "127.0.0.1" && runtime.ListenHost != "::1" {
		return false
	}
	if runtime.ListenPort < 0 || runtime.ListenPort > 65535 {
		return false
	}
	if len(runtime.ListenUsername) < 16 || len(runtime.ListenUsername) > 100 || len(runtime.ListenPassword) < 32 || len(runtime.ListenPassword) > 100 {
		return false
	}
	if runtime.Visibility != "private" && runtime.Visibility != "public" {
		return false
	}
	fallback := runtime.FallbackMode
	if fallback == "" {
		fallback = "none"
	}
	if fallback != "none" && fallback != "direct" && fallback != "proxy" {
		return false
	}
	if fallback == "proxy" && (runtime.BackupProxyID == nil || *runtime.BackupProxyID <= 0) {
		return false
	}
	if fallback != "proxy" && runtime.BackupProxyID != nil {
		return false
	}
	return true
}

func validEncryptedPurpose(value, purpose string) bool {
	parts := strings.SplitN(value, ":", 5)
	return len(parts) == 5 && parts[0] == "prx" && parts[1] == "v1" && parts[2] != "" && parts[3] == purpose && parts[4] != ""
}

func nullableInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func classifyRuntimeWriteError(err error) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "23505":
			return ErrProxyRuntimeConflict
		case "23503", "23514", "23502":
			return ErrProxyRuntimeInvalid
		}
	}
	return fmt.Errorf("persist native proxy runtime: %w", err)
}
