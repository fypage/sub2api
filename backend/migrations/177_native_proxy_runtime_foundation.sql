-- Native sing-box runtime foundation.
-- Additive only: existing static proxies and account bindings are unchanged.

CREATE TABLE IF NOT EXISTS proxy_runtime_sources (
    id BIGSERIAL PRIMARY KEY,
    owner_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    name VARCHAR(100) NOT NULL,
    source_type VARCHAR(32) NOT NULL,
    source_secret_encrypted TEXT NOT NULL,
    encryption_version SMALLINT NOT NULL DEFAULT 1,
    refresh_interval_minutes INT NOT NULL DEFAULT 0,
    etag TEXT,
    last_modified TEXT,
    last_sync_at TIMESTAMPTZ,
    last_sync_status VARCHAR(20) NOT NULL DEFAULT 'never',
    last_error_code VARCHAR(64),
    last_error_redacted TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT proxy_runtime_sources_type_check CHECK (
        source_type IN ('xray_link', 'singbox_json', 'singbox_subscription')
    ),
    CONSTRAINT proxy_runtime_sources_encryption_version_check CHECK (encryption_version > 0),
    CONSTRAINT proxy_runtime_sources_refresh_interval_check CHECK (refresh_interval_minutes >= 0),
    CONSTRAINT proxy_runtime_sources_sync_status_check CHECK (
        last_sync_status IN ('never', 'pending', 'success', 'partial', 'failed')
    )
);

CREATE TABLE IF NOT EXISTS proxy_runtimes (
    id BIGSERIAL PRIMARY KEY,
    proxy_id BIGINT NOT NULL UNIQUE REFERENCES proxies(id) ON DELETE CASCADE,
    source_id BIGINT REFERENCES proxy_runtime_sources(id) ON DELETE SET NULL,
    owner_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    visibility VARCHAR(16) NOT NULL DEFAULT 'private',
    engine VARCHAR(20) NOT NULL DEFAULT 'sing-box',
    normalized_config_encrypted TEXT NOT NULL,
    encryption_version SMALLINT NOT NULL DEFAULT 1,
    node_fingerprint VARCHAR(64) NOT NULL,
    listen_host VARCHAR(255) NOT NULL DEFAULT '127.0.0.1',
    listen_port INT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    pid BIGINT,
    restart_count INT NOT NULL DEFAULT 0,
    auto_start BOOLEAN NOT NULL DEFAULT TRUE,
    config_path TEXT,
    last_error_code VARCHAR(64),
    last_error_redacted TEXT,
    exit_ip INET,
    country_code VARCHAR(2),
    quality_score SMALLINT,
    quality_checked_at TIMESTAMPTZ,
    last_started_at TIMESTAMPTZ,
    last_stopped_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT proxy_runtimes_visibility_check CHECK (visibility IN ('private', 'public')),
    CONSTRAINT proxy_runtimes_engine_check CHECK (engine = 'sing-box'),
    CONSTRAINT proxy_runtimes_encryption_version_check CHECK (encryption_version > 0),
    CONSTRAINT proxy_runtimes_fingerprint_check CHECK (node_fingerprint ~ '^[0-9a-f]{64}$'),
    CONSTRAINT proxy_runtimes_port_check CHECK (listen_port BETWEEN 1 AND 65535),
    CONSTRAINT proxy_runtimes_status_check CHECK (
        status IN ('pending', 'starting', 'healthy', 'degraded', 'blocked', 'stopped', 'error')
    ),
    CONSTRAINT proxy_runtimes_restart_count_check CHECK (restart_count >= 0),
    CONSTRAINT proxy_runtimes_quality_score_check CHECK (
        quality_score IS NULL OR quality_score BETWEEN 0 AND 100
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_runtimes_active_owner_fingerprint
    ON proxy_runtimes (owner_user_id, node_fingerprint)
    WHERE deleted_at IS NULL AND owner_user_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_runtimes_active_system_fingerprint
    ON proxy_runtimes (node_fingerprint)
    WHERE deleted_at IS NULL AND owner_user_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_runtimes_active_listener
    ON proxy_runtimes (listen_host, listen_port)
    WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_proxy_runtimes_owner_visibility
    ON proxy_runtimes (owner_user_id, visibility)
    WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_proxy_runtimes_status
    ON proxy_runtimes (status)
    WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_proxy_runtimes_source_id
    ON proxy_runtimes (source_id)
    WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_proxy_runtime_sources_owner
    ON proxy_runtime_sources (owner_user_id)
    WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_proxy_runtime_sources_refresh_due
    ON proxy_runtime_sources (last_sync_at)
    WHERE deleted_at IS NULL AND source_type = 'singbox_subscription' AND refresh_interval_minutes > 0;

COMMENT ON TABLE proxy_runtimes IS 'Sub2API-managed native sing-box runtimes; bound through the existing proxies table.';
COMMENT ON COLUMN proxy_runtimes.normalized_config_encrypted IS 'Versioned encrypted canonical outbound/endpoint JSON; never return directly from list APIs.';
COMMENT ON COLUMN proxy_runtime_sources.source_secret_encrypted IS 'Versioned encrypted original share link, JSON, or subscription URL.';
