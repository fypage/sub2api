package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/lib/pq"
)

var (
	ErrProxyRuntimeNotFound      = errors.New("native proxy runtime not found")
	ErrProxyRuntimeStateConflict = errors.New("native proxy runtime state conflict")
	ErrProxyRuntimeLeaseReleased = errors.New("native proxy runtime lease released")
)

const maxRuntimeErrorText = 500

var runtimeErrorCodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

type ProxyRuntimeSnapshot struct {
	ID                        int64
	ProxyID                   int64
	NormalizedConfigEncrypted string
	EncryptionVersion         int16
	ListenHost                string
	ListenPort                int
	Status                    string
	AutoStart                 bool
	RestartCount              int
}

type ProxyRuntimeLease struct {
	conn      *sql.Conn
	runtimeID int64
}

func (r *ProxyRuntimeRepository) ListAutoStartRuntimeIDs(ctx context.Context, limit int) ([]int64, error) {
	if r == nil || r.db == nil {
		return nil, ErrProxyRuntimeInvalid
	}
	if limit <= 0 || limit > 512 {
		limit = 512
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT id FROM proxy_runtimes
WHERE deleted_at IS NULL AND auto_start = TRUE
ORDER BY id ASC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list native proxy runtimes for recovery: %w", err)
	}
	defer func() { _ = rows.Close() }()
	ids := make([]int64, 0, limit)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan native proxy runtime recovery candidate: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate native proxy runtime recovery candidates: %w", err)
	}
	return ids, nil
}

func (r *ProxyRuntimeRepository) TryAcquireLifecycleLease(ctx context.Context, runtimeID int64) (*ProxyRuntimeLease, bool, error) {
	if r == nil || r.db == nil || runtimeID <= 0 {
		return nil, false, ErrProxyRuntimeInvalid
	}
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("open native proxy runtime lease connection: %w", err)
	}
	var acquired bool
	if err := conn.QueryRowContext(ctx,
		"SELECT pg_try_advisory_lock(hashtextextended('proxy_runtime:' || $1::text, 0))", runtimeID).Scan(&acquired); err != nil {
		_ = conn.Close()
		return nil, false, fmt.Errorf("acquire native proxy runtime lease: %w", err)
	}
	if !acquired {
		_ = conn.Close()
		return nil, false, nil
	}
	return &ProxyRuntimeLease{conn: conn, runtimeID: runtimeID}, true, nil
}

func (l *ProxyRuntimeLease) Snapshot(ctx context.Context) (*ProxyRuntimeSnapshot, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}
	var snapshot ProxyRuntimeSnapshot
	err := l.conn.QueryRowContext(ctx, `
SELECT id, proxy_id, normalized_config_encrypted, encryption_version,
       listen_host, listen_port, status, auto_start, restart_count
FROM proxy_runtimes
WHERE id = $1 AND deleted_at IS NULL`, l.runtimeID).Scan(
		&snapshot.ID, &snapshot.ProxyID, &snapshot.NormalizedConfigEncrypted,
		&snapshot.EncryptionVersion, &snapshot.ListenHost, &snapshot.ListenPort,
		&snapshot.Status, &snapshot.AutoStart, &snapshot.RestartCount)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrProxyRuntimeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load native proxy runtime: %w", err)
	}
	return &snapshot, nil
}

func (l *ProxyRuntimeLease) MarkStarting(ctx context.Context) error {
	return l.transition(ctx, []string{"pending", "stopped", "error", "degraded", "blocked"}, `
WITH changed AS (
    UPDATE proxy_runtimes
    SET status = 'starting', pid = NULL, config_path = NULL,
        last_error_code = NULL, last_error_redacted = NULL,
        last_started_at = NOW(), updated_at = NOW()
    WHERE proxy_runtimes.id = $1 AND proxy_runtimes.deleted_at IS NULL AND status = ANY($2)
      AND EXISTS (SELECT 1 FROM proxies p WHERE p.id = proxy_runtimes.proxy_id AND p.deleted_at IS NULL)
    RETURNING proxy_id
)
UPDATE proxies p SET status = 'disabled', updated_at = NOW()
FROM changed WHERE p.id = changed.proxy_id`, nil)
}

func (l *ProxyRuntimeLease) MarkHealthy(ctx context.Context, pid int64, configPath string) error {
	if pid <= 0 || !filepath.IsAbs(configPath) || len(configPath) > 4096 {
		return ErrProxyRuntimeInvalid
	}
	return l.transition(ctx, []string{"starting"}, `
WITH changed AS (
    UPDATE proxy_runtimes
    SET status = 'healthy', pid = $3, config_path = $4,
        last_error_code = NULL, last_error_redacted = NULL, updated_at = NOW()
    WHERE proxy_runtimes.id = $1 AND proxy_runtimes.deleted_at IS NULL AND status = ANY($2)
      AND EXISTS (SELECT 1 FROM proxies p WHERE p.id = proxy_runtimes.proxy_id AND p.deleted_at IS NULL)
    RETURNING proxy_id
)
UPDATE proxies p SET status = 'active', updated_at = NOW()
FROM changed WHERE p.id = changed.proxy_id`, []any{pid, configPath})
}

func (l *ProxyRuntimeLease) MarkFailed(ctx context.Context, code, redacted string, countRestart bool) error {
	code = strings.TrimSpace(code)
	redacted = strings.TrimSpace(redacted)
	if !runtimeErrorCodePattern.MatchString(code) || redacted == "" || len(redacted) > maxRuntimeErrorText {
		return ErrProxyRuntimeInvalid
	}
	increment := 0
	if countRestart {
		increment = 1
	}
	return l.transition(ctx, []string{"pending", "starting", "healthy", "degraded", "blocked", "error"}, `
WITH changed AS (
    UPDATE proxy_runtimes
    SET status = 'error', pid = NULL,
        last_error_code = $3, last_error_redacted = $4,
        restart_count = restart_count + $5, updated_at = NOW()
    WHERE proxy_runtimes.id = $1 AND proxy_runtimes.deleted_at IS NULL AND status = ANY($2)
      AND EXISTS (SELECT 1 FROM proxies p WHERE p.id = proxy_runtimes.proxy_id AND p.deleted_at IS NULL)
    RETURNING proxy_id
)
UPDATE proxies p SET status = 'disabled', updated_at = NOW()
FROM changed WHERE p.id = changed.proxy_id`, []any{code, redacted, increment})
}

func (l *ProxyRuntimeLease) MarkStopped(ctx context.Context) error {
	return l.transition(ctx, []string{"pending", "starting", "healthy", "degraded", "blocked", "error", "stopped"}, `
WITH changed AS (
    UPDATE proxy_runtimes
    SET status = 'stopped', pid = NULL, last_stopped_at = NOW(), updated_at = NOW()
    WHERE proxy_runtimes.id = $1 AND proxy_runtimes.deleted_at IS NULL AND status = ANY($2)
      AND EXISTS (SELECT 1 FROM proxies p WHERE p.id = proxy_runtimes.proxy_id AND p.deleted_at IS NULL)
    RETURNING proxy_id
)
UPDATE proxies p SET status = 'disabled', updated_at = NOW()
FROM changed WHERE p.id = changed.proxy_id`, nil)
}

func (l *ProxyRuntimeLease) transition(ctx context.Context, allowed []string, query string, extra []any) error {
	if err := l.validate(); err != nil {
		return err
	}
	args := []any{l.runtimeID, pq.Array(allowed)}
	args = append(args, extra...)
	result, err := l.conn.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update native proxy runtime lifecycle: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect native proxy runtime lifecycle update: %w", err)
	}
	if changed != 1 {
		return ErrProxyRuntimeStateConflict
	}
	return nil
}

func (l *ProxyRuntimeLease) Release() {
	if l == nil || l.conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = l.conn.ExecContext(ctx,
		"SELECT pg_advisory_unlock(hashtextextended('proxy_runtime:' || $1::text, 0))", l.runtimeID)
	_ = l.conn.Close()
	l.conn = nil
}

func (l *ProxyRuntimeLease) validate() error {
	if l == nil || l.conn == nil || l.runtimeID <= 0 {
		return ErrProxyRuntimeLeaseReleased
	}
	return nil
}

// Lifecycle updates are executed through the same connection that owns the advisory lease.
