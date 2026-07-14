package proxyimport

import (
	"bytes"
	"fmt"
	"strings"
)

const maxSubscriptionItems = 512

type SubscriptionResult struct {
	Candidates []Result        `json:"candidates,omitempty"`
	JSONNodes  []JSONCandidate `json:"json_nodes,omitempty"`
	Failures   []ImportFailure `json:"failures,omitempty"`
}

type ImportFailure struct {
	Index int    `json:"index"`
	Code  string `json:"code"`
}

func ParseSubscription(input []byte) (*SubscriptionResult, error) {
	input = bytes.TrimSpace(input)
	if len(input) == 0 || len(input) > maxSingBoxJSONBytes {
		return nil, fmt.Errorf("%w: invalid subscription payload", ErrInvalidInput)
	}
	if input[0] == '{' || input[0] == '[' {
		nodes, err := ParseSingBoxJSON(input)
		if err != nil {
			return nil, err
		}
		return &SubscriptionResult{JSONNodes: nodes}, nil
	}
	text := string(input)
	if !containsShareScheme(text) {
		decoded, err := decodeBase64(strings.Join(strings.Fields(text), ""))
		if err != nil {
			return nil, fmt.Errorf("%w: unsupported subscription encoding", ErrInvalidInput)
		}
		text = string(decoded)
		decodedTrimmed := bytes.TrimSpace(decoded)
		if len(decodedTrimmed) > 0 && (decodedTrimmed[0] == '{' || decodedTrimmed[0] == '[') {
			nodes, parseErr := ParseSingBoxJSON(decodedTrimmed)
			if parseErr != nil {
				return nil, parseErr
			}
			return &SubscriptionResult{JSONNodes: nodes}, nil
		}
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	result := &SubscriptionResult{}
	seen := make(map[string]bool)
	itemIndex := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if itemIndex >= maxSubscriptionItems {
			return nil, fmt.Errorf("%w: too many subscription items", ErrInvalidInput)
		}
		candidate, err := ParseShareLink(line)
		if err != nil {
			result.Failures = append(result.Failures, ImportFailure{Index: itemIndex, Code: "invalid_share_link"})
		} else if !seen[candidate.Fingerprint] {
			seen[candidate.Fingerprint] = true
			result.Candidates = append(result.Candidates, *candidate)
		}
		itemIndex++
	}
	if itemIndex == 0 || len(result.Candidates) == 0 {
		return nil, fmt.Errorf("%w: no valid subscription nodes", ErrInvalidInput)
	}
	return result, nil
}

func containsShareScheme(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "vless://") || strings.Contains(lower, "vmess://") || strings.Contains(lower, "trojan://") || strings.Contains(lower, "ss://")
}
