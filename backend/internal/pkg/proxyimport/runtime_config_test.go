package proxyimport

import (
	"encoding/json"
	"strings"
	"testing"
)

func testListener() RuntimeListener {
	return RuntimeListener{Host: "127.0.0.1", Port: 21001, Username: "runtime-user-001", Password: strings.Repeat("p", 32)}
}

func decodeConfig(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func requireSlice(t *testing.T, value any, field string) []any {
	t.Helper()
	result, ok := value.([]any)
	if !ok {
		t.Fatalf("%s is not an array: %#v", field, value)
	}
	return result
}

func TestBuildShareLinkRuntimeConfigIsMinimalAndAuthenticated(t *testing.T) {
	result, err := ParseShareLink("trojan://secret@example.com:443?type=ws&path=%2Fws#node")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := BuildShareLinkRuntimeConfig(*result, testListener())
	if err != nil {
		t.Fatal(err)
	}
	config := decodeConfig(t, raw)
	if _, exists := config["dns"]; exists {
		t.Fatal("runtime config unexpectedly imported DNS policy")
	}
	inbounds := requireSlice(t, config["inbounds"], "inbounds")
	inbound := requireMap(t, inbounds[0], "inbounds[0]")
	if inbound["listen"] != "127.0.0.1" || inbound["listen_port"] != float64(21001) {
		t.Fatalf("unexpected listener: %#v", inbound)
	}
	users := requireSlice(t, inbound["users"], "users")
	if requireMap(t, users[0], "users[0]")["password"] != strings.Repeat("p", 32) {
		t.Fatal("listener authentication missing")
	}
	outbounds := requireSlice(t, config["outbounds"], "outbounds")
	if requireMap(t, outbounds[0], "outbounds[0]")["tag"] != "runtime-out-0" {
		t.Fatal("internal outbound tag missing")
	}
	if requireMap(t, config["route"], "route")["final"] != "runtime-out-0" {
		t.Fatal("route final does not target imported node")
	}
}

func TestBuildJSONRuntimeConfigRewritesDetourTags(t *testing.T) {
	candidates, err := ParseSingBoxJSON([]byte(`[{"type":"trojan","tag":"front","server":"one.example","server_port":443,"password":"one","detour":"exit"},{"type":"vless","tag":"exit","server":"two.example","server_port":443,"uuid":"` + testUUID + `"}]`))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := BuildJSONRuntimeConfig(candidates[0], testListener())
	if err != nil {
		t.Fatal(err)
	}
	config := decodeConfig(t, raw)
	outbounds := requireSlice(t, config["outbounds"], "outbounds")
	first := requireMap(t, outbounds[0], "outbounds[0]")
	second := requireMap(t, outbounds[1], "outbounds[1]")
	if first["tag"] != "runtime-out-0" || first["detour"] != "runtime-out-1" || second["tag"] != "runtime-out-1" {
		t.Fatalf("detour tags not rewritten: %#v", outbounds)
	}
	if strings.Contains(string(raw), `"tag":"front"`) || strings.Contains(string(raw), `"tag":"exit"`) {
		t.Fatal("user tags leaked into runtime config")
	}
}

func TestBuildJSONRuntimeConfigPreservesEndpointKind(t *testing.T) {
	candidates, err := ParseSingBoxJSON([]byte(`{"endpoints":[{"type":"wireguard","tag":"wg","address":["10.0.0.2/32"],"private_key":"secret","peers":[]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := BuildJSONRuntimeConfig(candidates[0], testListener())
	if err != nil {
		t.Fatal(err)
	}
	config := decodeConfig(t, raw)
	if _, exists := config["outbounds"]; exists {
		t.Fatal("endpoint was incorrectly emitted as outbound")
	}
	endpoints := requireSlice(t, config["endpoints"], "endpoints")
	if requireMap(t, endpoints[0], "endpoints[0]")["tag"] != "runtime-endpoint-0" {
		t.Fatal("endpoint tag missing")
	}
	if requireMap(t, config["route"], "route")["final"] != "runtime-endpoint-0" {
		t.Fatal("route final does not target endpoint")
	}
}

func TestBuildRuntimeConfigRejectsUnsafeListenerAndBrokenMaterials(t *testing.T) {
	validResult, _ := ParseShareLink("trojan://secret@example.com:443")
	badListeners := []RuntimeListener{
		{},
		{Host: "0.0.0.0", Port: 21001, Username: "runtime-user-001", Password: strings.Repeat("p", 32)},
		{Host: "127.0.0.1", Port: 21001, Username: "short", Password: strings.Repeat("p", 32)},
	}
	for _, listener := range badListeners {
		if _, err := BuildShareLinkRuntimeConfig(*validResult, listener); err == nil {
			t.Fatalf("unsafe listener accepted: %+v", listener)
		}
	}
	broken := JSONCandidate{Materials: []NodeMaterial{{Kind: "outbound", Raw: json.RawMessage(`{"type":"trojan","tag":"a","detour":"missing"}`)}}}
	if _, err := BuildJSONRuntimeConfig(broken, testListener()); err == nil {
		t.Fatal("unresolved detour must fail")
	}
	wrongKind := JSONCandidate{Materials: []NodeMaterial{{Kind: "file", Raw: json.RawMessage(`{"type":"trojan"}`)}}}
	if _, err := BuildJSONRuntimeConfig(wrongKind, testListener()); err == nil {
		t.Fatal("unknown material kind must fail")
	}
	unsafe := JSONCandidate{Materials: []NodeMaterial{{Kind: "outbound", Raw: json.RawMessage(`{"type":"trojan","certificate_path":"/etc/passwd"}`)}}}
	if _, err := BuildJSONRuntimeConfig(unsafe, testListener()); err == nil {
		t.Fatal("unsafe material must be revalidated")
	}
	unrelated := JSONCandidate{Materials: []NodeMaterial{
		{Kind: "outbound", Raw: json.RawMessage(`{"type":"trojan","tag":"main"}`)},
		{Kind: "outbound", Raw: json.RawMessage(`{"type":"vless","tag":"extra"}`)},
	}}
	if _, err := BuildJSONRuntimeConfig(unrelated, testListener()); err == nil {
		t.Fatal("unrelated material must fail")
	}
}
