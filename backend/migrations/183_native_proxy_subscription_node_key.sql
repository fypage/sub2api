-- Stable, non-secret identity for a selected node inside a subscription.
-- The key hashes protocol + subscription node name. Existing rows remain NULL
-- because their original selector cannot be reconstructed safely.

ALTER TABLE proxy_runtimes
    ADD COLUMN IF NOT EXISTS source_node_key VARCHAR(64);

ALTER TABLE proxy_runtimes
    DROP CONSTRAINT IF EXISTS proxy_runtimes_source_node_key_check;
ALTER TABLE proxy_runtimes
    ADD CONSTRAINT proxy_runtimes_source_node_key_check CHECK (
        source_node_key IS NULL OR source_node_key ~ '^[0-9a-f]{64}$'
    );

CREATE INDEX IF NOT EXISTS idx_proxy_runtimes_active_source_node_key
    ON proxy_runtimes (source_id, source_node_key)
    WHERE deleted_at IS NULL AND source_id IS NOT NULL AND source_node_key IS NOT NULL;

COMMENT ON COLUMN proxy_runtimes.source_node_key IS
    'Non-secret stable hash of protocol and source node name; used to distinguish subscription updates from removals.';
