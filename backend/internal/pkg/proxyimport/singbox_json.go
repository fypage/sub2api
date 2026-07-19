package proxyimport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	maxSingBoxJSONBytes = 2 << 20
	maxJSONDepth        = 64
	maxJSONNodes        = 512
	maxJSONStringBytes  = 64 << 10
)

type JSONCandidate struct {
	Name         string         `json:"name"`
	Protocol     string         `json:"protocol"`
	ServerHint   string         `json:"server_hint,omitempty"`
	Dependencies int            `json:"dependencies"`
	Fingerprint  string         `json:"fingerprint"`
	Materials    []NodeMaterial `json:"-"`
}

type NodeMaterial struct {
	Kind string          `json:"kind"`
	Raw  json.RawMessage `json:"-"`
}

type rawNode struct {
	Type   string `json:"type"`
	Tag    string `json:"tag"`
	Server string `json:"server"`
	Detour string `json:"detour"`
}

func ParseSingBoxJSON(input []byte) ([]JSONCandidate, error) {
	input = bytes.TrimSpace(input)
	if len(input) == 0 || len(input) > maxSingBoxJSONBytes || !validJSONResources(input) {
		return nil, fmt.Errorf("%w: invalid sing-box json", ErrInvalidInput)
	}
	raws, kinds, err := extractNodeObjects(input)
	if err != nil || len(raws) == 0 || len(raws) > maxJSONNodes {
		return nil, fmt.Errorf("%w: invalid sing-box json shape", ErrInvalidInput)
	}
	nodes := make([]rawNode, len(raws))
	byTag := make(map[string]int, len(raws))
	for i, raw := range raws {
		if err := json.Unmarshal(raw, &nodes[i]); err != nil || strings.TrimSpace(nodes[i].Type) == "" {
			return nil, fmt.Errorf("%w: invalid sing-box node", ErrInvalidInput)
		}
		if err := validateNodeSafety(raw); err != nil {
			return nil, err
		}
		nodes[i].Type = strings.ToLower(strings.TrimSpace(nodes[i].Type))
		nodes[i].Tag = strings.TrimSpace(nodes[i].Tag)
		nodes[i].Detour = strings.TrimSpace(nodes[i].Detour)
		if len(raws) > 1 && nodes[i].Tag == "" {
			return nil, fmt.Errorf("%w: tag required for multiple nodes", ErrInvalidInput)
		}
		if nodes[i].Tag != "" {
			if _, exists := byTag[nodes[i].Tag]; exists {
				return nil, fmt.Errorf("%w: duplicate sing-box tag", ErrInvalidInput)
			}
			byTag[nodes[i].Tag] = i
		}
	}

	candidates := make([]JSONCandidate, 0, len(raws))
	for i := range nodes {
		if !isImportableNode(nodes[i].Type, kinds[i]) {
			continue
		}
		chain, err := resolveDetourChain(i, nodes, kinds, byTag)
		if err != nil {
			return nil, err
		}
		canonical, material, err := canonicalizeChain(chain, raws, kinds)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(canonical)
		name := nodes[i].Tag
		if name == "" {
			name = nodes[i].Type
		}
		candidates = append(candidates, JSONCandidate{
			Name: name, Protocol: nodes[i].Type, ServerHint: serverHint(nodes[i].Server),
			Dependencies: len(chain) - 1, Fingerprint: hex.EncodeToString(sum[:]), Materials: material,
		})
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("%w: no importable sing-box nodes", ErrInvalidInput)
	}
	return candidates, nil
}

func extractNodeObjects(input []byte) ([]json.RawMessage, []string, error) {
	if input[0] == '[' {
		var result []json.RawMessage
		if err := json.Unmarshal(input, &result); err != nil {
			return nil, nil, err
		}
		kinds := make([]string, len(result))
		for i := range kinds {
			kinds[i] = "outbound"
		}
		return result, kinds, nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(input, &object); err != nil {
		return nil, nil, err
	}
	if _, single := object["type"]; single {
		kind := "outbound"
		if _, hasAddress := object["address"]; hasAddress {
			if _, hasPeers := object["peers"]; hasPeers {
				kind = "endpoint"
			}
		}
		return []json.RawMessage{append(json.RawMessage(nil), input...)}, []string{kind}, nil
	}
	var result []json.RawMessage
	var kinds []string
	for _, key := range []string{"outbounds", "endpoints"} {
		if raw, exists := object[key]; exists {
			var values []json.RawMessage
			if err := json.Unmarshal(raw, &values); err != nil {
				return nil, nil, err
			}
			result = append(result, values...)
			kind := strings.TrimSuffix(key, "s")
			for range values {
				kinds = append(kinds, kind)
			}
		}
	}
	return result, kinds, nil
}

func resolveDetourChain(start int, nodes []rawNode, kinds []string, byTag map[string]int) ([]int, error) {
	chain := []int{start}
	seen := map[int]bool{start: true}
	current := start
	for nodes[current].Detour != "" {
		next, ok := byTag[nodes[current].Detour]
		if !ok {
			return nil, fmt.Errorf("%w: missing detour dependency", ErrInvalidInput)
		}
		if seen[next] {
			return nil, fmt.Errorf("%w: cyclic detour dependency", ErrInvalidInput)
		}
		if !isImportableNode(nodes[next].Type, kinds[next]) || kinds[current] != "outbound" || kinds[next] != "outbound" {
			return nil, fmt.Errorf("%w: unsafe detour dependency", ErrInvalidInput)
		}
		seen[next] = true
		chain = append(chain, next)
		current = next
	}
	return chain, nil
}

func canonicalizeChain(chain []int, raws []json.RawMessage, kinds []string) ([]byte, []NodeMaterial, error) {
	canonical := make([]map[string]any, 0, len(chain))
	material := make([]NodeMaterial, 0, len(chain))
	for position, index := range chain {
		var object map[string]any
		decoder := json.NewDecoder(bytes.NewReader(raws[index]))
		decoder.UseNumber()
		if err := decoder.Decode(&object); err != nil {
			return nil, nil, fmt.Errorf("%w: invalid sing-box node", ErrInvalidInput)
		}
		delete(object, "tag")
		if position+1 < len(chain) {
			object["detour"] = fmt.Sprintf("@dependency:%d", position+1)
		} else {
			delete(object, "detour")
		}
		object["@kind"] = kinds[index]
		canonical = append(canonical, object)
		material = append(material, NodeMaterial{Kind: kinds[index], Raw: append(json.RawMessage(nil), raws[index]...)})
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalize sing-box node: %w", err)
	}
	return encoded, material, nil
}

func isImportableNode(protocol, kind string) bool {
	if kind == "endpoint" {
		return protocol == "wireguard"
	}
	if kind != "outbound" {
		return false
	}
	switch protocol {
	case "shadowsocks", "vmess", "trojan", "hysteria", "vless", "shadowtls", "tuic", "hysteria2", "anytls", "snell", "naive":
		return true
	default:
		return false
	}
}

func validateNodeSafety(raw json.RawMessage) error {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("%w: invalid sing-box node", ErrInvalidInput)
	}
	forbidden := map[string]bool{
		"netns": true, "bind_interface": true, "routing_mark": true,
		"domain_resolver": true, "executable": true, "data_directory": true,
	}
	var walk func(any) bool
	walk = func(current any) bool {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				if forbidden[key] || strings.HasSuffix(key, "_path") {
					return false
				}
				if !walk(child) {
					return false
				}
			}
		case []any:
			for _, child := range typed {
				if !walk(child) {
					return false
				}
			}
		}
		return true
	}
	if !walk(value) {
		return fmt.Errorf("%w: unsafe sing-box host capability", ErrInvalidInput)
	}
	return nil
}

func validJSONResources(input []byte) bool {
	depth, stringBytes := 0, 0
	inString, escaped := false, false
	for _, value := range input {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if value == '\\' {
				escaped = true
				continue
			}
			if value == '"' {
				inString = false
				stringBytes = 0
				continue
			}
			stringBytes++
			if stringBytes > maxJSONStringBytes {
				return false
			}
			continue
		}
		switch value {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > maxJSONDepth {
				return false
			}
		case '}', ']':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return !inString && depth == 0 && json.Valid(input)
}
