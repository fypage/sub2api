package migrations

import (
	"strings"
	"testing"
)

func TestNativeProxySubscriptionNodeKeyMigrationIsAdditive(t *testing.T) {
	content, err := FS.ReadFile("183_native_proxy_subscription_node_key.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(content)
	for _, required := range []string{
		"ADD COLUMN IF NOT EXISTS source_node_key VARCHAR(64)",
		"source_node_key ~ '^[0-9a-f]{64}$'",
		"idx_proxy_runtimes_active_source_node_key",
		"WHERE deleted_at IS NULL AND source_id IS NOT NULL AND source_node_key IS NOT NULL",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration missing %q", required)
		}
	}
	if strings.Contains(strings.ToUpper(sql), "UPDATE PROXY_RUNTIMES") {
		t.Fatal("migration must not guess stable keys for existing secret-bearing rows")
	}
}
