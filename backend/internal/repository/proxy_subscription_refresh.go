package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type ProxySubscriptionRefreshCandidate struct {
	SourceID              int64
	SourceSecretEncrypted string
	ETag                  string
	LastModified          string
}

type ProxySubscriptionRefreshLease struct {
	conn     *sql.Conn
	sourceID int64
}

func (r *ProxyRuntimeRepository) TryAcquireSubscriptionRefreshLease(ctx context.Context, sourceID int64) (*ProxySubscriptionRefreshLease, bool, error) {
	if r == nil || r.db == nil || sourceID <= 0 {
		return nil, false, ErrProxyRuntimeInvalid
	}
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return nil, false, err
	}
	var acquired bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock(hashtextextended('proxy_subscription:' || $1::text, 0))", sourceID).Scan(&acquired); err != nil {
		_ = conn.Close()
		return nil, false, err
	}
	if !acquired {
		_ = conn.Close()
		return nil, false, nil
	}
	return &ProxySubscriptionRefreshLease{conn: conn, sourceID: sourceID}, true, nil
}

func (l *ProxySubscriptionRefreshLease) Release() {
	if l == nil || l.conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = l.conn.ExecContext(ctx, "SELECT pg_advisory_unlock(hashtextextended('proxy_subscription:' || $1::text, 0))", l.sourceID)
	_ = l.conn.Close()
	l.conn = nil
}

type ProxySubscriptionRuntime struct {
	RuntimeID     int64
	ProxyID       int64
	Fingerprint   string
	SourceNodeKey string
}

func (r *ProxyRuntimeRepository) ListDueSubscriptionSources(ctx context.Context, limit int) ([]ProxySubscriptionRefreshCandidate, error) {
	if r == nil || r.db == nil {
		return nil, ErrProxyRuntimeInvalid
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT id, source_secret_encrypted, COALESCE(etag, ''), COALESCE(last_modified, '')
FROM proxy_runtime_sources
WHERE deleted_at IS NULL AND source_type = 'singbox_subscription'
  AND refresh_interval_minutes > 0
  AND (last_sync_at IS NULL OR last_sync_at + make_interval(mins => refresh_interval_minutes) <= NOW())
ORDER BY COALESCE(last_sync_at, created_at) ASC
LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list due proxy subscriptions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]ProxySubscriptionRefreshCandidate, 0, limit)
	for rows.Next() {
		var item ProxySubscriptionRefreshCandidate
		if err := rows.Scan(&item.SourceID, &item.SourceSecretEncrypted, &item.ETag, &item.LastModified); err != nil {
			return nil, fmt.Errorf("scan due proxy subscription: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate due proxy subscriptions: %w", err)
	}
	return result, nil
}

func (r *ProxyRuntimeRepository) ListSourceRuntimes(ctx context.Context, sourceID int64) ([]ProxySubscriptionRuntime, error) {
	if r == nil || r.db == nil || sourceID <= 0 {
		return nil, ErrProxyRuntimeInvalid
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT id, proxy_id, node_fingerprint, COALESCE(source_node_key, '')
FROM proxy_runtimes
WHERE source_id = $1 AND deleted_at IS NULL
ORDER BY id`, sourceID)
	if err != nil {
		return nil, fmt.Errorf("list subscription runtimes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var result []ProxySubscriptionRuntime
	for rows.Next() {
		var item ProxySubscriptionRuntime
		if err := rows.Scan(&item.RuntimeID, &item.ProxyID, &item.Fingerprint, &item.SourceNodeKey); err != nil {
			return nil, fmt.Errorf("scan subscription runtime: %w", err)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *ProxyRuntimeRepository) RecordSubscriptionSync(ctx context.Context, sourceID int64, status, etag, modified, code, text string) error {
	if r == nil || r.db == nil || sourceID <= 0 {
		return ErrProxyRuntimeInvalid
	}
	if status != "success" && status != "partial" && status != "failed" {
		return ErrProxyRuntimeInvalid
	}
	if len(code) > 64 || len(text) > 500 {
		return ErrProxyRuntimeInvalid
	}
	result, err := r.db.ExecContext(ctx, `
UPDATE proxy_runtime_sources
SET last_sync_at = NOW(), last_sync_status = $2,
    etag = CASE WHEN $3 = '' THEN etag ELSE $3 END,
    last_modified = CASE WHEN $4 = '' THEN last_modified ELSE $4 END,
    last_error_code = NULLIF($5, ''), last_error_redacted = NULLIF($6, ''),
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL`, sourceID, status, etag, modified, code, text)
	if err != nil {
		return fmt.Errorf("record proxy subscription sync: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *ProxyRuntimeRepository) RecordSubscriptionDeferred(ctx context.Context, sourceID int64) error {
	if r == nil || r.db == nil || sourceID <= 0 {
		return ErrProxyRuntimeInvalid
	}
	result, err := r.db.ExecContext(ctx, `
UPDATE proxy_runtime_sources
SET last_sync_at = NULL, last_sync_status = 'partial',
    last_error_code = 'subscription_update_deferred',
    last_error_redacted = 'subscription update deferred', updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL`, sourceID)
	if err != nil {
		return fmt.Errorf("defer proxy subscription sync: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *ProxyRuntimeRepository) MarkSubscriptionRuntimeRemoved(ctx context.Context, runtimeID int64) error {
	if r == nil || r.db == nil || runtimeID <= 0 {
		return ErrProxyRuntimeInvalid
	}
	result, err := r.db.ExecContext(ctx, `
WITH changed AS (
  UPDATE proxy_runtimes
  SET status = 'error', auto_start = FALSE, pid = NULL,
      last_error_code = 'subscription_node_removed',
      last_error_redacted = 'node was removed from subscription', updated_at = NOW()
  WHERE id = $1 AND deleted_at IS NULL
  RETURNING proxy_id
)
UPDATE proxies p SET status = 'disabled', updated_at = NOW()
FROM changed WHERE p.id = changed.proxy_id`, runtimeID)
	if err != nil {
		return fmt.Errorf("disable removed subscription runtime: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return errors.New("subscription runtime state changed concurrently")
	}
	return nil
}

// Refresh policy never auto-creates replacement nodes or rebinds accounts.
