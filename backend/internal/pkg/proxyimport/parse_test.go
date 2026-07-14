package proxyimport

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const testUUID = "bf000d23-0752-40b4-affe-68f7707a9661"

func decodeOutbound(t *testing.T, result *Result) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(result.Outbound, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestParseVLESSRealityWebSocket(t *testing.T) {
	link := "vless://" + testUUID + "@Example.COM:443?type=ws&security=reality&sni=cdn.example.com&fp=chrome&pbk=public-key&sid=abcd&host=edge.example.com&path=%2Fws#Primary"
	result, err := ParseShareLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "Primary" || result.Protocol != "vless" || result.Server != "example.com" || result.ServerPort != 443 {
		t.Fatalf("unexpected preview: %+v", result)
	}
	if len(result.Fingerprint) != 64 || strings.Contains(string(result.Outbound), "Primary") {
		t.Fatal("fingerprint or canonical name handling is invalid")
	}
	out := decodeOutbound(t, result)
	tls := out["tls"].(map[string]any)
	if tls["server_name"] != "cdn.example.com" {
		t.Fatalf("unexpected tls: %#v", tls)
	}
	reality := tls["reality"].(map[string]any)
	if reality["public_key"] != "public-key" || reality["short_id"] != "abcd" {
		t.Fatalf("unexpected reality: %#v", reality)
	}
	transport := out["transport"].(map[string]any)
	if transport["type"] != "ws" || transport["path"] != "/ws" {
		t.Fatalf("unexpected transport: %#v", transport)
	}
}

func TestParseTrojanGRPCDefaultsTLS(t *testing.T) {
	result, err := ParseShareLink("trojan://top-secret@example.com:443?type=grpc&serviceName=api&sni=example.com#Trojan")
	if err != nil {
		t.Fatal(err)
	}
	out := decodeOutbound(t, result)
	if out["password"] != "top-secret" {
		t.Fatal("password was not preserved in encrypted outbound material")
	}
	if out["tls"].(map[string]any)["enabled"] != true {
		t.Fatal("trojan must default to TLS")
	}
	if out["transport"].(map[string]any)["service_name"] != "api" {
		t.Fatal("grpc service name missing")
	}
}

func TestParseVMessStandardJSON(t *testing.T) {
	payload := `{"v":"2","ps":"VMess Node","add":"Vmess.EXAMPLE.com","port":"8443","id":"` + testUUID + `","aid":"0","scy":"auto","net":"ws","host":"host.example.com","path":"/socket","tls":"tls","sni":"sni.example.com","alpn":"h2,http/1.1","fp":"chrome","type":"none"}`
	link := "vmess://" + base64.RawStdEncoding.EncodeToString([]byte(payload))
	result, err := ParseShareLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "VMess Node" || result.Server != "vmess.example.com" || result.ServerPort != 8443 {
		t.Fatalf("unexpected result: %+v", result)
	}
	out := decodeOutbound(t, result)
	if out["security"] != "auto" || out["uuid"] != testUUID {
		t.Fatalf("unexpected vmess: %#v", out)
	}
}

func TestParseShadowsocksSIP002Forms(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:p@ss:word"))
	forms := []string{
		"ss://aes-256-gcm:p%40ss%3Aword@SS.Example.com:8388#plain",
		"ss://" + userinfo + "@ss.example.com:8388#userinfo",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:p@ss:word@[2001:db8::1]:8388")) + "#legacy",
	}
	for _, link := range forms {
		result, err := ParseShareLink(link)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		out := decodeOutbound(t, result)
		if out["method"] != "aes-256-gcm" || out["password"] != "p@ss:word" {
			t.Fatalf("unexpected shadowsocks: %#v", out)
		}
	}
}

func TestFingerprintStableAcrossNamesAndQueryOrder(t *testing.T) {
	a, err := ParseShareLink("vless://" + testUUID + "@EXAMPLE.com:443?security=tls&type=ws&path=%2Fx&sni=edge.example#one")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseShareLink("vless://" + testUUID + "@example.com:443?sni=edge.example&path=%2Fx&type=ws&security=tls#two")
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint != b.Fingerprint || string(a.Outbound) != string(b.Outbound) {
		t.Fatal("equivalent nodes must have stable canonical identity")
	}
}

func TestFingerprintChangesWithSecretOrTransport(t *testing.T) {
	base, _ := ParseShareLink("trojan://secret@example.com:443?type=ws&path=%2Fa")
	secret, _ := ParseShareLink("trojan://different@example.com:443?type=ws&path=%2Fa")
	path, _ := ParseShareLink("trojan://secret@example.com:443?type=ws&path=%2Fb")
	if base.Fingerprint == secret.Fingerprint || base.Fingerprint == path.Fingerprint {
		t.Fatal("credential and transport changes must alter fingerprint")
	}
}

func TestStrictRejectionAndSecretSafeErrors(t *testing.T) {
	secret := "do-not-leak-this"
	cases := []string{
		"ftp://" + secret + "@example.com:21",
		"trojan://" + secret + "@example.com:443?allowInsecure=1",
		"trojan://" + secret + "@example.com:443?security=none",
		"trojan://" + secret + "@example.com:443?type=kcp",
		"vless://" + testUUID + "@example.com:443?encryption=legacy",
		"vless://bad-id@example.com:443",
		"vless://" + testUUID + "@example.com:443?security=reality",
		"ss://unsupported:" + secret + "@example.com:8388",
	}
	for _, input := range cases {
		_, err := ParseShareLink(input)
		if err == nil || !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("expected invalid input for %q, got %v", input, err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaked secret: %v", err)
		}
	}
}

func TestResultJSONNeverExposesOutboundSecrets(t *testing.T) {
	result, err := ParseShareLink("trojan://do-not-expose@example.com:443#safe-name")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "do-not-expose") || strings.Contains(string(encoded), "outbound") {
		t.Fatalf("public result leaked secret material: %s", encoded)
	}
}

func TestInputBoundsAndInvalidPorts(t *testing.T) {
	for _, input := range []string{"", strings.Repeat("x", 64*1024+1), "trojan://secret@example.com:0", "trojan://secret@example.com:70000"} {
		if _, err := ParseShareLink(input); err == nil {
			t.Fatalf("expected rejection for input length %d", len(input))
		}
	}
}
