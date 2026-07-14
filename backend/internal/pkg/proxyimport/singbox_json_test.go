package proxyimport

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestParseSingBoxJSONAcceptedShapes(t *testing.T) {
	single := `{"type":"vless","server":"node.example.com","server_port":443,"uuid":"` + testUUID + `"}`
	array := `[` + single + `]`
	config := `{"outbounds":[{"type":"direct","tag":"direct"},{"type":"trojan","tag":"proxy","server":"edge.example.com","server_port":443,"password":"secret"}],"route":{"final":"proxy"}}`
	for _, input := range []string{single, array, config} {
		candidates, err := ParseSingBoxJSON([]byte(input))
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		if len(candidates) != 1 || len(candidates[0].Fingerprint) != 64 || len(candidates[0].Materials) != 1 {
			t.Fatalf("unexpected candidates: %+v", candidates)
		}
	}
}

func TestParseSingBoxJSONFiltersLogicalOutbounds(t *testing.T) {
	input := `{"outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"block"},{"type":"dns","tag":"dns"},{"type":"selector","tag":"select","outbounds":["proxy"]},{"type":"urltest","tag":"auto","outbounds":["proxy"]},{"type":"vmess","tag":"proxy","server":"vm.example","server_port":443,"uuid":"` + testUUID + `"}]}`
	candidates, err := ParseSingBoxJSON([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Name != "proxy" || candidates[0].Protocol != "vmess" {
		t.Fatalf("logical outbounds were imported: %+v", candidates)
	}
}

func TestParseSingBoxJSONResolvesRemoteDetourChain(t *testing.T) {
	input := `{"outbounds":[{"type":"shadowsocks","tag":"entry","server":"one.example","server_port":8388,"method":"aes-256-gcm","password":"one","detour":"middle"},{"type":"trojan","tag":"middle","server":"two.example","server_port":443,"password":"two","detour":"exit"},{"type":"vless","tag":"exit","server":"three.example","server_port":443,"uuid":"` + testUUID + `"}]}`
	candidates, err := ParseSingBoxJSON([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 3 || candidates[0].Dependencies != 2 || len(candidates[0].Materials) != 3 {
		t.Fatalf("unexpected dependency chain: %+v", candidates)
	}
}

func TestParseSingBoxJSONRejectsBrokenUnsafeAndCyclicDetours(t *testing.T) {
	cases := []string{
		`[{"type":"trojan","tag":"a","detour":"missing"}]`,
		`[{"type":"trojan","tag":"a","detour":"direct"},{"type":"direct","tag":"direct"}]`,
		`[{"type":"trojan","tag":"a","detour":"b"},{"type":"vless","tag":"b","detour":"a"}]`,
		`[{"type":"trojan","tag":"same"},{"type":"vless","tag":"same"}]`,
		`{"outbounds":[{"type":"trojan","tag":"a","detour":"wg"}],"endpoints":[{"type":"wireguard","tag":"wg","address":["10.0.0.2/32"],"peers":[]}]}`,
		`[{"type":"trojan"},{"type":"vless","tag":"b"}]`,
	}
	for _, input := range cases {
		_, err := ParseSingBoxJSON([]byte(input))
		if err == nil || !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("expected rejection for %s: %v", input, err)
		}
	}
}

func TestParseSingBoxJSONFingerprintIgnoresTagsButTracksDetour(t *testing.T) {
	first := `[{"type":"trojan","tag":"front-a","server":"front.example","server_port":443,"password":"secret","detour":"exit-a"},{"type":"vless","tag":"exit-a","server":"exit.example","server_port":443,"uuid":"` + testUUID + `"}]`
	second := `[{"type":"trojan","tag":"front-b","server":"front.example","server_port":443,"password":"secret","detour":"exit-b"},{"type":"vless","tag":"exit-b","server":"exit.example","server_port":443,"uuid":"` + testUUID + `"}]`
	a, err := ParseSingBoxJSON([]byte(first))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseSingBoxJSON([]byte(second))
	if err != nil {
		t.Fatal(err)
	}
	if a[0].Fingerprint != b[0].Fingerprint {
		t.Fatal("renaming tags changed canonical fingerprint")
	}
	changed := strings.Replace(second, "exit.example", "other.example", 1)
	c, err := ParseSingBoxJSON([]byte(changed))
	if err != nil {
		t.Fatal(err)
	}
	if a[0].Fingerprint == c[0].Fingerprint {
		t.Fatal("dependency content change did not alter fingerprint")
	}
}

func TestParseSingBoxJSONPublicResultDoesNotLeakMaterial(t *testing.T) {
	candidates, err := ParseSingBoxJSON([]byte(`{"type":"trojan","tag":"private","server":"secret.example.com","server_port":443,"password":"do-not-expose"}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(candidates)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, "do-not-expose") || strings.Contains(text, "secret.example.com") || strings.Contains(text, "outbounds") || strings.Contains(text, "raw") {
		t.Fatalf("candidate leaked secret material: %s", text)
	}
	materialJSON, err := json.Marshal(candidates[0].Materials[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(materialJSON), "do-not-expose") || strings.Contains(string(materialJSON), "raw") {
		t.Fatalf("material leaked raw node: %s", materialJSON)
	}
}

func TestParseSingBoxJSONRejectsHostCapabilitiesAndStatefulProtocols(t *testing.T) {
	cases := []string{
		`{"type":"vless","tag":"a","server":"example.com","certificate_path":"/etc/passwd"}`,
		`{"type":"trojan","tag":"a","server":"example.com","bind_interface":"eth0"}`,
		`{"type":"vmess","tag":"a","server":"example.com","tls":{"ech":{"config_path":"/secret"}}}`,
		`{"type":"ssh","tag":"a","server":"example.com","private_key_path":"/root/.ssh/id"}`,
		`{"type":"tor","tag":"a","executable":"/tmp/tor"}`,
	}
	for _, input := range cases {
		_, err := ParseSingBoxJSON([]byte(input))
		if err == nil || !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("expected host capability rejection: %s: %v", input, err)
		}
	}
}

func TestParseSingBoxJSONPreservesLargeIntegerFingerprint(t *testing.T) {
	a, err := ParseSingBoxJSON([]byte(`{"type":"trojan","server":"example.com","server_port":443,"custom_id":9007199254740992}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseSingBoxJSON([]byte(`{"type":"trojan","server":"example.com","server_port":443,"custom_id":9007199254740993}`))
	if err != nil {
		t.Fatal(err)
	}
	if a[0].Fingerprint == b[0].Fingerprint {
		t.Fatal("large integer precision was lost during canonicalization")
	}
}

func TestParseSingBoxJSONEndpointsAndResourceLimits(t *testing.T) {
	candidates, err := ParseSingBoxJSON([]byte(`{"endpoints":[{"type":"wireguard","tag":"wg","address":["10.0.0.2/32"],"private_key":"secret","peers":[]},{"type":"tailscale","tag":"ts"}]}`))
	if err != nil || len(candidates) != 1 || candidates[0].Protocol != "wireguard" {
		t.Fatalf("unexpected endpoint result: %+v %v", candidates, err)
	}
	if len(candidates[0].Materials) != 1 || candidates[0].Materials[0].Kind != "endpoint" {
		t.Fatalf("endpoint material kind was lost: %+v", candidates[0].Materials)
	}
	tooDeep := strings.Repeat("[", maxJSONDepth+1) + "0" + strings.Repeat("]", maxJSONDepth+1)
	tooLongString := `{"type":"trojan","password":"` + strings.Repeat("x", maxJSONStringBytes+1) + `"}`
	tooLarge := make([]byte, maxSingBoxJSONBytes+1)
	for _, input := range [][]byte{[]byte(""), []byte(tooDeep), []byte(tooLongString), tooLarge} {
		if _, err := ParseSingBoxJSON(input); err == nil {
			t.Fatalf("expected resource rejection for %d bytes", len(input))
		}
	}
}
