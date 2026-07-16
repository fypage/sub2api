package repository

import "testing"

func TestRuntimeSourceNodeKeyIsStableAndNonSecret(t *testing.T) {
	first := runtimeSourceNodeKey(" VLESS ", " node-a ")
	if first == "" || len(first) != 64 {
		t.Fatalf("invalid source node key %q", first)
	}
	if first != runtimeSourceNodeKey("vless", "node-a") {
		t.Fatal("normalization changed the stable source node key")
	}
	if first == runtimeSourceNodeKey("trojan", "node-a") || first == runtimeSourceNodeKey("vless", "node-b") {
		t.Fatal("protocol or name change did not change source node key")
	}
	if runtimeSourceNodeKey("", "node-a") != "" || runtimeSourceNodeKey("vless", "") != "" {
		t.Fatal("incomplete source identity produced a key")
	}
}
