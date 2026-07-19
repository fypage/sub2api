package repository

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

func (r *ProxyRuntimeRepository) UpdateQualityByProxyID(ctx context.Context, proxyID int64, snapshot service.ProxyRuntimeQualitySnapshot) error {
	if r == nil || r.db == nil || proxyID <= 0 || snapshot.Score < 0 || snapshot.Score > 100 {
		return ErrProxyRuntimeInvalid
	}
	if snapshot.Status != "healthy" && snapshot.Status != "degraded" && snapshot.Status != "blocked" {
		return ErrProxyRuntimeInvalid
	}
	if snapshot.ExitIP != "" && net.ParseIP(snapshot.ExitIP) == nil {
		return ErrProxyRuntimeInvalid
	}
	country := strings.ToUpper(strings.TrimSpace(snapshot.CountryCode))
	if country != "" && len(country) != 2 {
		return ErrProxyRuntimeInvalid
	}
	code := strings.TrimSpace(snapshot.ErrorCode)
	text := strings.TrimSpace(snapshot.ErrorText)
	if code != "" && !runtimeErrorCodePattern.MatchString(code) {
		return ErrProxyRuntimeInvalid
	}
	if len(text) > maxRuntimeErrorText {
		return ErrProxyRuntimeInvalid
	}
	result, err := r.db.ExecContext(ctx, `
WITH changed AS (
    UPDATE proxy_runtimes
    SET status = $2, quality_score = $3, exit_ip = NULLIF($4, '')::inet,
        country_code = NULLIF($5, ''), quality_checked_at = NOW(),
        last_error_code = NULLIF($6, ''), last_error_redacted = NULLIF($7, ''),
        updated_at = NOW()
    WHERE proxy_id = $1 AND deleted_at IS NULL
    RETURNING proxy_id
)
UPDATE proxies p
SET status = CASE WHEN $2 = 'healthy' THEN 'active' ELSE 'disabled' END,
    updated_at = NOW()
FROM changed WHERE p.id = changed.proxy_id`, proxyID, snapshot.Status, snapshot.Score,
		snapshot.ExitIP, country, code, text)
	if err != nil {
		return fmt.Errorf("update native proxy runtime quality: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect native proxy runtime quality update: %w", err)
	}
	if rows == 0 {
		// Static proxies intentionally have no native runtime row.
		return nil
	}
	return nil
}
