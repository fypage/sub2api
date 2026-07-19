package proxyimport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

type RuntimeListener struct {
	Host     string
	Port     int
	Username string
	Password string
}

func BuildShareLinkRuntimeConfig(result Result, listener RuntimeListener) ([]byte, error) {
	if len(result.Outbound) == 0 {
		return nil, fmt.Errorf("%w: missing normalized outbound", ErrInvalidInput)
	}
	material := NodeMaterial{Kind: "outbound", Raw: result.Outbound}
	return buildRuntimeConfig([]NodeMaterial{material}, listener)
}

func BuildJSONRuntimeConfig(candidate JSONCandidate, listener RuntimeListener) ([]byte, error) {
	if len(candidate.Materials) == 0 {
		return nil, fmt.Errorf("%w: missing node materials", ErrInvalidInput)
	}
	return buildRuntimeConfig(candidate.Materials, listener)
}

// BuildCanonicalRuntimeConfig reconstructs a validated runtime configuration
// from the canonical encrypted node chain persisted by the import workflow.
func EncodeCanonicalCandidate(candidate JSONCandidate) ([]byte, error) {
	if len(candidate.Materials) == 0 || len(candidate.Materials) > maxJSONNodes {
		return nil, fmt.Errorf("%w: missing canonical materials", ErrInvalidInput)
	}
	objects := make([]map[string]any, len(candidate.Materials))
	for index, material := range candidate.Materials {
		decoder := json.NewDecoder(bytes.NewReader(material.Raw))
		decoder.UseNumber()
		if err := decoder.Decode(&objects[index]); err != nil {
			return nil, fmt.Errorf("%w: invalid canonical material", ErrInvalidInput)
		}
		delete(objects[index], "tag")
		objects[index]["@kind"] = material.Kind
		if index+1 < len(objects) {
			objects[index]["detour"] = fmt.Sprintf("@dependency:%d", index+1)
		} else {
			delete(objects[index], "detour")
		}
	}
	encoded, err := json.Marshal(objects)
	if err != nil {
		return nil, fmt.Errorf("encode canonical candidate: %w", err)
	}
	return encoded, nil
}

func BuildCanonicalRuntimeConfig(canonical []byte, listener RuntimeListener) ([]byte, error) {
	canonical = bytes.TrimSpace(canonical)
	if len(canonical) == 0 || len(canonical) > maxSingBoxJSONBytes {
		return nil, fmt.Errorf("%w: invalid canonical node chain", ErrInvalidInput)
	}
	// Share-link imports persist one normalized outbound object, while JSON
	// imports persist the canonical dependency array produced by ParseSingBoxJSON.
	if canonical[0] == '{' {
		candidates, err := ParseSingBoxJSON(canonical)
		if err != nil || len(candidates) != 1 {
			return nil, fmt.Errorf("%w: invalid canonical single node", ErrInvalidInput)
		}
		return BuildJSONRuntimeConfig(candidates[0], listener)
	}
	var objects []map[string]any
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	if err := decoder.Decode(&objects); err != nil || len(objects) == 0 || len(objects) > maxJSONNodes {
		return nil, fmt.Errorf("%w: invalid canonical node chain", ErrInvalidInput)
	}
	materials := make([]NodeMaterial, 0, len(objects))
	for index, object := range objects {
		kind, ok := object["@kind"].(string)
		if !ok || (kind != "outbound" && kind != "endpoint") {
			return nil, fmt.Errorf("%w: invalid canonical material kind", ErrInvalidInput)
		}
		delete(object, "@kind")
		if index+1 < len(objects) {
			expected := fmt.Sprintf("@dependency:%d", index+1)
			if object["detour"] != expected || kind != "outbound" {
				return nil, fmt.Errorf("%w: invalid canonical dependency", ErrInvalidInput)
			}
			object["tag"] = fmt.Sprintf("canonical-%d", index)
			object["detour"] = fmt.Sprintf("canonical-%d", index+1)
		} else {
			delete(object, "detour")
			object["tag"] = fmt.Sprintf("canonical-%d", index)
		}
		raw, err := json.Marshal(object)
		if err != nil {
			return nil, fmt.Errorf("marshal canonical node: %w", err)
		}
		materials = append(materials, NodeMaterial{Kind: kind, Raw: raw})
	}
	return buildRuntimeConfig(materials, listener)
}

func buildRuntimeConfig(materials []NodeMaterial, listener RuntimeListener) ([]byte, error) {
	if !validRuntimeListener(listener) || len(materials) == 0 || len(materials) > maxJSONNodes {
		return nil, fmt.Errorf("%w: invalid runtime config input", ErrInvalidInput)
	}
	outbounds := make([]map[string]any, 0, len(materials))
	endpoints := make([]map[string]any, 0, 1)
	tagMap := make(map[string]string, len(materials))
	objects := make([]map[string]any, len(materials))
	for i, material := range materials {
		if material.Kind != "outbound" && material.Kind != "endpoint" {
			return nil, fmt.Errorf("%w: invalid node material kind", ErrInvalidInput)
		}
		decoder := json.NewDecoder(bytes.NewReader(material.Raw))
		decoder.UseNumber()
		if err := decoder.Decode(&objects[i]); err != nil || strings.TrimSpace(asString(objects[i]["type"])) == "" {
			return nil, fmt.Errorf("%w: invalid node material", ErrInvalidInput)
		}
		if err := validateNodeSafety(material.Raw); err != nil || !isImportableNode(strings.ToLower(asString(objects[i]["type"])), material.Kind) {
			return nil, fmt.Errorf("%w: unsafe node material", ErrInvalidInput)
		}
		if material.Kind == "endpoint" && strings.TrimSpace(asString(objects[i]["detour"])) != "" {
			return nil, fmt.Errorf("%w: endpoint detour is not supported", ErrInvalidInput)
		}
		oldTag := strings.TrimSpace(asString(objects[i]["tag"]))
		newTag := fmt.Sprintf("runtime-out-%d", i)
		if material.Kind == "endpoint" {
			newTag = fmt.Sprintf("runtime-endpoint-%d", i)
		}
		if oldTag != "" {
			if _, duplicate := tagMap[oldTag]; duplicate {
				return nil, fmt.Errorf("%w: duplicate node material tag", ErrInvalidInput)
			}
			tagMap[oldTag] = newTag
		}
	}
	if err := validateMaterialChain(objects, materials); err != nil {
		return nil, err
	}
	for i, material := range materials {
		internalTag := fmt.Sprintf("runtime-out-%d", i)
		if material.Kind == "endpoint" {
			internalTag = fmt.Sprintf("runtime-endpoint-%d", i)
		}
		objects[i]["tag"] = internalTag
		if detour := strings.TrimSpace(asString(objects[i]["detour"])); detour != "" {
			rewritten, ok := tagMap[detour]
			if !ok {
				return nil, fmt.Errorf("%w: unresolved runtime detour", ErrInvalidInput)
			}
			objects[i]["detour"] = rewritten
		}
		if material.Kind == "outbound" {
			outbounds = append(outbounds, objects[i])
		} else {
			endpoints = append(endpoints, objects[i])
		}
	}
	mainTag := asString(objects[0]["tag"])
	config := map[string]any{
		"log": map[string]any{"disabled": true},
		"inbounds": []any{map[string]any{
			"type": "socks", "tag": "runtime-in", "listen": listener.Host, "listen_port": listener.Port,
			"users": []any{map[string]any{"username": listener.Username, "password": listener.Password}},
		}},
		"route": map[string]any{"final": mainTag},
	}
	if len(outbounds) > 0 {
		config["outbounds"] = outbounds
	}
	if len(endpoints) > 0 {
		config["endpoints"] = endpoints
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("marshal runtime config: %w", err)
	}
	return encoded, nil
}

func validateMaterialChain(objects []map[string]any, materials []NodeMaterial) error {
	if len(objects) == 1 && materials[0].Kind == "endpoint" {
		return nil
	}
	byTag := make(map[string]int, len(objects))
	for i, object := range objects {
		tag := strings.TrimSpace(asString(object["tag"]))
		if tag != "" {
			byTag[tag] = i
		}
	}
	used := map[int]bool{}
	current := 0
	for {
		if used[current] {
			return fmt.Errorf("%w: cyclic runtime materials", ErrInvalidInput)
		}
		used[current] = true
		detour := strings.TrimSpace(asString(objects[current]["detour"]))
		if detour == "" {
			break
		}
		next, ok := byTag[detour]
		if !ok || materials[current].Kind != "outbound" || materials[next].Kind != "outbound" {
			return fmt.Errorf("%w: unresolved runtime detour", ErrInvalidInput)
		}
		current = next
	}
	if len(used) != len(objects) {
		return fmt.Errorf("%w: unrelated runtime material", ErrInvalidInput)
	}
	return nil
}

func validRuntimeListener(listener RuntimeListener) bool {
	if listener.Host != "127.0.0.1" && listener.Host != "::1" {
		return false
	}
	return listener.Port >= 1 && listener.Port <= 65535 && len(listener.Username) >= 16 && len(listener.Username) <= 100 && len(listener.Password) >= 32 && len(listener.Password) <= 100
}

func asString(value any) string {
	result, _ := value.(string)
	return result
}
