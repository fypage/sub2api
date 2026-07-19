package repository

import (
	"context"
	"strings"
	"testing"
)

func TestParseRuntimePayloadSupportsOfflineShareLinks(t *testing.T) {
	share, nodes, err := parseRuntimePayload("trojan://secret@example.com:443#node")
	if err != nil || len(share) != 1 || len(nodes) != 0 {
		t.Fatalf("share payload parse failed: %d %d %v", len(share), len(nodes), err)
	}
	if strings.Contains(share[0].ServerHint, "secret") {
		t.Fatal("preview leaked share credential")
	}
}

func TestProxyRuntimeAdminRejectsURLWithoutFetcher(t *testing.T) {
	admin := &ProxyRuntimeAdmin{manager: &ProxyRuntimeManager{enabled: true}}
	if _, err := admin.Preview(context.Background(), "https://example.com/sub"); err == nil {
		t.Fatal("subscription URL accepted without secure fetcher")
	}
}
