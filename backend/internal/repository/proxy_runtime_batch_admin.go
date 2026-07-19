package repository

import (
	"context"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/proxyimport"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func (a *ProxyRuntimeAdmin) CreateBatch(ctx context.Context, request service.ProxyRuntimeBatchCreateRequest) ([]service.ProxyRuntimeCreated, error) {
	if a == nil || a.repository == nil || a.manager == nil || a.keyring == nil || !a.manager.enabled || len(request.Fingerprints) == 0 || len(request.Fingerprints) > 100 {
		return nil, ErrProxyRuntimeInvalid
	}
	payload, source, err := a.resolveRuntimeInput(ctx, request.Input)
	if err != nil {
		return nil, err
	}
	share, nodes, err := parseRuntimePayload(payload)
	if err != nil {
		return nil, err
	}
	selected := make(map[string]bool, len(request.Fingerprints))
	for _, fingerprint := range request.Fingerprints {
		fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
		if !runtimeFingerprintPattern.MatchString(fingerprint) || selected[fingerprint] {
			return nil, ErrProxyRuntimeInvalid
		}
		selected[fingerprint] = true
	}
	inputs := make([]ProxyRuntimeCreateInput, 0, len(selected))
	appendInput := func(name, protocol, fingerprint string, canonical []byte) error {
		if !selected[fingerprint] {
			return nil
		}
		encrypted, err := a.keyring.Encrypt("config", canonical)
		clear(canonical)
		if err != nil {
			return err
		}
		username, err := randomRuntimeCredential(18)
		if err != nil {
			return err
		}
		password, err := randomRuntimeCredential(32)
		if err != nil {
			return err
		}
		inputs = append(inputs, ProxyRuntimeCreateInput{
			Name: name, Visibility: request.Visibility,
			NormalizedConfigEncrypted: encrypted, EncryptionVersion: 1,
			NodeFingerprint: fingerprint, SourceNodeKey: runtimeSourceNodeKey(protocol, name),
			ListenHost: "127.0.0.1", ListenPort: 0,
			ListenUsername: username, ListenPassword: password,
			FallbackMode: request.FallbackMode, BackupProxyID: request.BackupProxyID,
		})
		return nil
	}
	for _, candidate := range share {
		if err := appendInput(candidate.Name, candidate.Protocol, candidate.Fingerprint, append([]byte(nil), candidate.Outbound...)); err != nil {
			return nil, err
		}
	}
	for _, candidate := range nodes {
		if !selected[candidate.Fingerprint] {
			continue
		}
		canonical, err := proxyimport.EncodeCanonicalCandidate(candidate)
		if err != nil {
			return nil, err
		}
		if err := appendInput(candidate.Name, candidate.Protocol, candidate.Fingerprint, canonical); err != nil {
			return nil, err
		}
	}
	if len(inputs) != len(selected) {
		return nil, ErrProxyRuntimeInvalid
	}
	persisted, err := a.repository.CreateBatch(ctx, ProxyRuntimeBatchInput{OwnerUserID: request.OwnerUserID, Source: source, Runtimes: inputs})
	if err != nil {
		return nil, err
	}
	result := make([]service.ProxyRuntimeCreated, 0, len(persisted.Items))
	for _, created := range persisted.Items {
		status := "error"
		if err := a.manager.Start(ctx, created.RuntimeID); err == nil {
			if current, statusErr := a.repository.GetRuntimeStatusByProxyID(ctx, created.ProxyID); statusErr == nil {
				status = current.Status
			}
		}
		result = append(result, service.ProxyRuntimeCreated{ProxyID: created.ProxyID, RuntimeID: created.RuntimeID, Status: status})
	}
	return result, nil
}

// Batch persistence is atomic; process startup and quality results are itemized.
