package proxyimport

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseSubscriptionPlainAndBase64Lists(t *testing.T) {
	plain := strings.Join([]string{
		"# provider comment",
		"vless://" + testUUID + "@one.example:443?security=tls#one",
		"not-a-link-containing-secret",
		"trojan://password@two.example:443#two",
		"trojan://password@two.example:443#duplicate-name",
	}, "\n")
	for _, payload := range [][]byte{[]byte(plain), []byte(base64.RawStdEncoding.EncodeToString([]byte(plain)))} {
		result, err := ParseSubscription(payload)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Candidates) != 2 || len(result.Failures) != 1 || result.Failures[0].Index != 1 {
			t.Fatalf("unexpected subscription result: %+v", result)
		}
	}
}

func TestParseSubscriptionSingBoxJSON(t *testing.T) {
	payload := []byte(`{"outbounds":[{"type":"vless","tag":"node","server":"example.com","server_port":443,"uuid":"` + testUUID + `"}]}`)
	result, err := ParseSubscription(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.JSONNodes) != 1 || len(result.Candidates) != 0 {
		t.Fatalf("unexpected JSON subscription: %+v", result)
	}
	encoded := []byte(base64.RawStdEncoding.EncodeToString(payload))
	decodedResult, err := ParseSubscription(encoded)
	if err != nil || len(decodedResult.JSONNodes) != 1 {
		t.Fatalf("unexpected encoded JSON subscription: %+v %v", decodedResult, err)
	}
}

func TestParseSubscriptionFailureSerializationIsSecretSafe(t *testing.T) {
	result, err := ParseSubscription([]byte("bad-secret-value\ntrojan://password@example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, "bad-secret") || strings.Contains(text, "password") || strings.Contains(text, "example.com") {
		t.Fatalf("subscription result leaked input: %s", text)
	}
}

func TestParseSubscriptionRejectsEmptyInvalidAndExcessiveLists(t *testing.T) {
	tooMany := strings.Repeat("trojan://p@example.com:443\n", maxSubscriptionItems+1)
	for _, input := range [][]byte{nil, []byte("not base64 or links"), []byte("bad\ninvalid"), []byte(tooMany)} {
		if _, err := ParseSubscription(input); err == nil {
			t.Fatalf("expected subscription rejection for %d bytes", len(input))
		}
	}
}
