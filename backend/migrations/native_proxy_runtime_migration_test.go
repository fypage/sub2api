package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigration177NativeProxyRuntimeFoundationIsAdditiveAndGuarded(t *testing.T) {
	content, err := FS.ReadFile("177_native_proxy_runtime_foundation.sql")
	require.NoError(t, err)
	sql := string(content)

	require.Contains(t, sql, "CREATE TABLE IF NOT EXISTS proxy_runtime_sources")
	require.Contains(t, sql, "CREATE TABLE IF NOT EXISTS proxy_runtimes")
	require.Contains(t, sql, "proxy_id BIGINT NOT NULL UNIQUE REFERENCES proxies(id) ON DELETE CASCADE")
	require.Contains(t, sql, "owner_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL")
	require.Contains(t, sql, "visibility IN ('private', 'public')")
	require.Contains(t, sql, "engine = 'sing-box'")
	require.Contains(t, sql, "source_type IN ('xray_link', 'singbox_json', 'singbox_subscription')")
	require.Contains(t, sql, "status IN ('pending', 'starting', 'healthy', 'degraded', 'blocked', 'stopped', 'error')")
	require.Contains(t, sql, "node_fingerprint ~ '^[0-9a-f]{64}$'")
	require.Contains(t, sql, "listen_port BETWEEN 1 AND 65535")
	require.Contains(t, sql, "quality_score IS NULL OR quality_score BETWEEN 0 AND 100")
	require.Contains(t, sql, "idx_proxy_runtimes_active_listener")
	require.Contains(t, sql, "idx_proxy_runtimes_active_owner_fingerprint")
	require.Contains(t, sql, "idx_proxy_runtimes_active_system_fingerprint")

	lower := strings.ToLower(sql)
	require.NotContains(t, lower, "alter table accounts")
	require.NotContains(t, lower, "alter table proxies")
	require.NotContains(t, lower, "insert into scheduler_outbox")
	require.NotContains(t, lower, "drop table")
	require.NotContains(t, lower, "drop column")
}

func TestMigration177KeepsSecretsEncryptedAndVersioned(t *testing.T) {
	content, err := FS.ReadFile("177_native_proxy_runtime_foundation.sql")
	require.NoError(t, err)
	sql := string(content)

	require.Contains(t, sql, "source_secret_encrypted TEXT NOT NULL")
	require.Contains(t, sql, "normalized_config_encrypted TEXT NOT NULL")
	require.Equal(t, 2, strings.Count(sql, "encryption_version SMALLINT NOT NULL DEFAULT 1"))
	require.NotContains(t, sql, "raw_link")
	require.NotContains(t, sql, "raw_config")
}
