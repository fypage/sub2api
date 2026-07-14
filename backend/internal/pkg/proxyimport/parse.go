// Package proxyimport parses secret-bearing proxy share links into canonical
// sing-box outbound JSON. Errors never include the original input.
package proxyimport

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var ErrInvalidInput = errors.New("invalid proxy share link")

type Result struct {
	Name        string          `json:"name"`
	Protocol    string          `json:"protocol"`
	ServerHint  string          `json:"server_hint"`
	ServerPort  uint16          `json:"server_port"`
	Fingerprint string          `json:"fingerprint"`
	Outbound    json.RawMessage `json:"-"`
}

type outbound struct {
	Type       string         `json:"type"`
	Server     string         `json:"server"`
	ServerPort uint16         `json:"server_port"`
	UUID       string         `json:"uuid,omitempty"`
	Password   string         `json:"password,omitempty"`
	Method     string         `json:"method,omitempty"`
	Security   string         `json:"security,omitempty"`
	AlterID    int            `json:"alter_id,omitempty"`
	Flow       string         `json:"flow,omitempty"`
	Plugin     string         `json:"plugin,omitempty"`
	PluginOpts string         `json:"plugin_opts,omitempty"`
	TLS        map[string]any `json:"tls,omitempty"`
	Transport  map[string]any `json:"transport,omitempty"`
}

func ParseShareLink(raw string) (*Result, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 64*1024 {
		return nil, ErrInvalidInput
	}
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd <= 0 {
		return nil, ErrInvalidInput
	}
	switch strings.ToLower(raw[:schemeEnd]) {
	case "vless", "trojan":
		return parseURLLink(raw)
	case "vmess":
		if parsed, err := url.Parse(raw); err == nil && parsed.User != nil && parsed.Hostname() != "" {
			return parseURLLink(raw)
		}
		return parseVMess(raw[schemeEnd+3:])
	case "ss":
		return parseShadowsocks(raw)
	default:
		return nil, fmt.Errorf("%w: unsupported scheme", ErrInvalidInput)
	}
}

func finish(name string, out outbound) (*Result, error) {
	canonical, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("marshal normalized outbound: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return &Result{Name: name, Protocol: out.Type, ServerHint: serverHint(out.Server), ServerPort: out.ServerPort, Fingerprint: hex.EncodeToString(sum[:]), Outbound: canonical}, nil
}

func parseURLLink(raw string) (*Result, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil || u.Hostname() == "" {
		return nil, ErrInvalidInput
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return nil, err
	}
	secret := u.User.Username()
	if secret == "" {
		return nil, ErrInvalidInput
	}
	protocol := strings.ToLower(u.Scheme)
	out := outbound{Type: protocol, Server: normalizeServer(u.Hostname()), ServerPort: port}
	if protocol == "vless" || protocol == "vmess" {
		if !validUUID(secret) {
			return nil, fmt.Errorf("%w: invalid user id", ErrInvalidInput)
		}
		encryption := strings.TrimSpace(u.Query().Get("encryption"))
		if protocol == "vless" {
			if encryption != "" && encryption != "none" {
				return nil, fmt.Errorf("%w: unsupported vless encryption", ErrInvalidInput)
			}
			out.Flow = u.Query().Get("flow")
		} else {
			if encryption == "" {
				encryption = "auto"
			}
			if !validVMessSecurity(encryption) {
				return nil, fmt.Errorf("%w: unsupported vmess encryption", ErrInvalidInput)
			}
			out.Security = encryption
		}
		out.UUID = strings.ToLower(secret)
	} else {
		out.Password = secret
	}
	if err := validateQuery(u.Query(), commonQueryKeys(protocol)); err != nil {
		return nil, err
	}
	out.TLS, err = parseTLS(u.Query(), protocol == "trojan")
	if err != nil {
		return nil, err
	}
	out.Transport, err = parseTransport(u.Query())
	if err != nil {
		return nil, err
	}
	return finish(fragmentName(u.Fragment, protocol), out)
}

func parseVMess(encoded string) (*Result, error) {
	data, err := decodeBase64(strings.TrimSpace(encoded))
	if err != nil || len(data) > 64*1024 {
		return nil, ErrInvalidInput
	}
	var v struct {
		Version any    `json:"v"`
		Name    string `json:"ps"`
		Server  string `json:"add"`
		Port    any    `json:"port"`
		UUID    string `json:"id"`
		AlterID any    `json:"aid"`
		Cipher  string `json:"scy"`
		Network string `json:"net"`
		Host    string `json:"host"`
		Path    string `json:"path"`
		TLS     string `json:"tls"`
		SNI     string `json:"sni"`
		ALPN    string `json:"alpn"`
		FP      string `json:"fp"`
		Type    string `json:"type"`
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil || strings.TrimSpace(v.Server) == "" || !validUUID(v.UUID) {
		return nil, ErrInvalidInput
	}
	port, err := anyPort(v.Port)
	if err != nil {
		return nil, err
	}
	aid, err := anyNonNegativeInt(v.AlterID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid alter id", ErrInvalidInput)
	}
	cipher := strings.TrimSpace(v.Cipher)
	if cipher == "" {
		cipher = "auto"
	}
	out := outbound{Type: "vmess", Server: normalizeServer(v.Server), ServerPort: port, UUID: strings.ToLower(v.UUID), Security: cipher, AlterID: aid}
	q := make(url.Values)
	q.Set("type", v.Network)
	q.Set("host", v.Host)
	q.Set("path", v.Path)
	q.Set("security", v.TLS)
	q.Set("sni", v.SNI)
	q.Set("alpn", v.ALPN)
	q.Set("fp", v.FP)
	if strings.EqualFold(v.Network, "grpc") {
		q.Set("serviceName", v.Path)
	}
	out.TLS, err = parseTLS(q, false)
	if err != nil {
		return nil, err
	}
	out.Transport, err = parseTransport(q)
	if err != nil {
		return nil, err
	}
	return finish(fragmentName(v.Name, "vmess"), out)
}

func parseShadowsocks(raw string) (*Result, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, ErrInvalidInput
	}
	name := fragmentName(u.Fragment, "shadowsocks")
	var method, password, server, portText string
	if u.Hostname() != "" && u.User != nil {
		userinfo := u.User.Username()
		if urlPassword, ok := u.User.Password(); ok {
			userinfo += ":" + urlPassword
		} else if decoded, decErr := decodeBase64(userinfo); decErr == nil {
			userinfo = string(decoded)
		}
		method, password, err = splitSSUserInfo(userinfo)
		server, portText = u.Hostname(), u.Port()
	} else {
		payload := strings.TrimPrefix(raw, "ss://")
		payload = strings.SplitN(payload, "#", 2)[0]
		payload = strings.SplitN(payload, "?", 2)[0]
		decoded, decErr := decodeBase64(payload)
		if decErr != nil {
			return nil, ErrInvalidInput
		}
		at := strings.LastIndexByte(string(decoded), '@')
		if at <= 0 {
			return nil, ErrInvalidInput
		}
		method, password, err = splitSSUserInfo(string(decoded[:at]))
		if err != nil {
			return nil, ErrInvalidInput
		}
		server, portText, err = splitHostPort(string(decoded[at+1:]))
	}
	if err != nil || server == "" {
		return nil, ErrInvalidInput
	}
	port, err := parsePort(portText)
	if err != nil {
		return nil, err
	}
	if !validSSMethod(method) {
		return nil, fmt.Errorf("%w: unsupported shadowsocks method", ErrInvalidInput)
	}
	out := outbound{Type: "shadowsocks", Server: normalizeServer(server), ServerPort: port, Method: method, Password: password}
	plugin := u.Query().Get("plugin")
	if plugin != "" {
		parts := strings.SplitN(plugin, ";", 2)
		if parts[0] != "obfs-local" && parts[0] != "v2ray-plugin" {
			return nil, fmt.Errorf("%w: unsupported shadowsocks plugin", ErrInvalidInput)
		}
		out.Plugin = parts[0]
		if len(parts) == 2 {
			out.PluginOpts = parts[1]
		}
	}
	return finish(name, out)
}

func parseTLS(q url.Values, defaultEnabled bool) (map[string]any, error) {
	security := strings.ToLower(strings.TrimSpace(q.Get("security")))
	if defaultEnabled && security == "none" {
		return nil, fmt.Errorf("%w: trojan requires tls", ErrInvalidInput)
	}
	enabled := defaultEnabled || security == "tls" || security == "reality"
	if security != "" && security != "none" && security != "tls" && security != "reality" {
		return nil, fmt.Errorf("%w: unsupported security", ErrInvalidInput)
	}
	if !enabled {
		return nil, nil
	}
	tls := map[string]any{"enabled": true}
	if sni := strings.TrimSpace(q.Get("sni")); sni != "" {
		tls["server_name"] = sni
	}
	if alpn := csv(q.Get("alpn")); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	if fp := strings.TrimSpace(q.Get("fp")); fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	if security == "reality" {
		pbk, sid := strings.TrimSpace(q.Get("pbk")), strings.TrimSpace(q.Get("sid"))
		if pbk == "" {
			return nil, fmt.Errorf("%w: reality public key required", ErrInvalidInput)
		}
		tls["reality"] = map[string]any{"enabled": true, "public_key": pbk, "short_id": sid}
	}
	return tls, nil
}

func parseTransport(q url.Values) (map[string]any, error) {
	typ := strings.ToLower(strings.TrimSpace(q.Get("type")))
	if typ == "" || typ == "tcp" {
		return nil, nil
	}
	switch typ {
	case "ws":
		t := map[string]any{"type": "ws"}
		setString(t, "path", q.Get("path"))
		if host := strings.TrimSpace(q.Get("host")); host != "" {
			t["headers"] = map[string]string{"Host": host}
		}
		return t, nil
	case "grpc":
		service := q.Get("serviceName")
		if service == "" {
			service = q.Get("path")
		}
		t := map[string]any{"type": "grpc"}
		setString(t, "service_name", service)
		return t, nil
	case "httpupgrade":
		t := map[string]any{"type": "httpupgrade"}
		setString(t, "host", q.Get("host"))
		setString(t, "path", q.Get("path"))
		return t, nil
	case "http", "h2":
		t := map[string]any{"type": "http"}
		if host := csv(q.Get("host")); len(host) > 0 {
			t["host"] = host
		}
		setString(t, "path", q.Get("path"))
		return t, nil
	default:
		return nil, fmt.Errorf("%w: unsupported transport", ErrInvalidInput)
	}
}

func commonQueryKeys(protocol string) map[string]bool {
	keys := map[string]bool{"type": true, "security": true, "sni": true, "fp": true, "pbk": true, "sid": true, "alpn": true, "host": true, "path": true, "serviceName": true}
	if protocol == "vless" {
		keys["flow"] = true
		keys["encryption"] = true
	}
	if protocol == "vmess" {
		keys["encryption"] = true
	}
	return keys
}

func validateQuery(q url.Values, allowed map[string]bool) error {
	for key, values := range q {
		if !allowed[key] {
			return fmt.Errorf("%w: unsupported parameter", ErrInvalidInput)
		}
		if len(values) != 1 {
			return fmt.Errorf("%w: repeated parameter", ErrInvalidInput)
		}
	}
	return nil
}

func parsePort(text string) (uint16, error) {
	value, err := strconv.ParseUint(strings.TrimSpace(text), 10, 16)
	if err != nil || value == 0 {
		return 0, fmt.Errorf("%w: invalid port", ErrInvalidInput)
	}
	return uint16(value), nil
}

func anyPort(value any) (uint16, error) { return parsePort(anyString(value)) }
func anyNonNegativeInt(value any) (int, error) {
	if value == nil || anyString(value) == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(anyString(value))
	if err != nil || n < 0 {
		return 0, ErrInvalidInput
	}
	return n, nil
}
func anyString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		return v.String()
	default:
		return ""
	}
}
func decodeBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(value); err == nil {
			return b, nil
		}
	}
	return nil, ErrInvalidInput
}
func splitSSUserInfo(value string) (string, string, error) {
	method, password, ok := strings.Cut(value, ":")
	if !ok || method == "" || password == "" {
		return "", "", ErrInvalidInput
	}
	return method, password, nil
}
func splitHostPort(value string) (string, string, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", "", ErrInvalidInput
	}
	return host, port, nil
}
func normalizeServer(value string) string { return strings.ToLower(strings.TrimSpace(value)) }
func serverHint(value string) string {
	if ip := net.ParseIP(value); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return fmt.Sprintf("%d.%d.x.x", v4[0], v4[1])
		}
		parts := strings.Split(value, ":")
		if len(parts) > 2 {
			return parts[0] + ":" + parts[1] + ":…"
		}
		return "ip"
	}
	if len(value) <= 4 {
		return "…"
	}
	return value[:2] + "…" + value[len(value)-3:]
}
func fragmentName(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
func csv(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
func setString(target map[string]any, key, value string) {
	if value = strings.TrimSpace(value); value != "" {
		target[key] = value
	}
}
func validUUID(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 36 {
		return false
	}
	for i, r := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}
func validVMessSecurity(value string) bool {
	switch value {
	case "auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305":
		return true
	default:
		return false
	}
}

func validSSMethod(method string) bool {
	switch method {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "rc4-md5", "chacha20-ietf", "xchacha20":
		return true
	}
	return false
}
