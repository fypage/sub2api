package repository

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/proxyimport"
	"github.com/Wei-Shaw/sub2api/internal/pkg/runtimecrypto"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

type ProxyRuntimeAdmin struct {
	repository *ProxyRuntimeRepository
	manager    *ProxyRuntimeManager
	keyring    *runtimecrypto.Keyring
	fetcher    *ProxySubscriptionFetcher
}

func NewProxyRuntimeAdmin(repo *ProxyRuntimeRepository, manager *ProxyRuntimeManager, keyring *runtimecrypto.Keyring, fetcher *ProxySubscriptionFetcher) *ProxyRuntimeAdmin {
	return &ProxyRuntimeAdmin{repository: repo, manager: manager, keyring: keyring, fetcher: fetcher}
}

func (a *ProxyRuntimeAdmin) Preview(ctx context.Context, input string) ([]service.ProxyRuntimePreview, error) {
	if a == nil || a.manager == nil || !a.manager.enabled {
		return nil, ErrProxyRuntimeInvalid
	}
	payload, _, err := a.resolveRuntimeInput(ctx, input)
	if err != nil {
		return nil, err
	}
	share, jsonNodes, err := parseRuntimePayload(payload)
	if err != nil {
		return nil, err
	}
	previews := make([]service.ProxyRuntimePreview, 0, len(share)+len(jsonNodes))
	for _, candidate := range share {
		previews = append(previews, service.ProxyRuntimePreview{Name: candidate.Name, Protocol: candidate.Protocol, ServerHint: candidate.ServerHint, Fingerprint: candidate.Fingerprint})
	}
	for _, candidate := range jsonNodes {
		previews = append(previews, service.ProxyRuntimePreview{Name: candidate.Name, Protocol: candidate.Protocol, ServerHint: candidate.ServerHint, Dependencies: candidate.Dependencies, Fingerprint: candidate.Fingerprint})
	}
	return previews, nil
}

func (a *ProxyRuntimeAdmin) Status(ctx context.Context, proxyID int64) (*service.ProxyRuntimeStatus, error) {
	if a == nil || a.repository == nil || a.manager == nil || !a.manager.enabled {
		return nil, ErrProxyRuntimeInvalid
	}
	status, err := a.repository.GetRuntimeStatusByProxyID(ctx, proxyID)
	if err != nil {
		return nil, err
	}
	return &service.ProxyRuntimeStatus{
		ID: status.ID, ProxyID: status.ProxyID, Status: status.Status,
		AutoStart: status.AutoStart, RestartCount: status.RestartCount,
		LastErrorCode: status.LastErrorCode, LastErrorRedacted: status.LastErrorRedacted,
		ListenHost: status.ListenHost, ListenPort: status.ListenPort,
	}, nil
}

func (a *ProxyRuntimeAdmin) RecordQuality(ctx context.Context, proxyID int64, snapshot service.ProxyRuntimeQualitySnapshot) error {
	if a == nil || a.repository == nil {
		return ErrProxyRuntimeInvalid
	}
	return a.repository.UpdateQualityByProxyID(ctx, proxyID, snapshot)
}

func (a *ProxyRuntimeAdmin) Start(ctx context.Context, runtimeID int64) error {
	if a == nil || a.manager == nil {
		return ErrProxyRuntimeInvalid
	}
	return a.manager.Start(ctx, runtimeID)
}

func (a *ProxyRuntimeAdmin) Stop(ctx context.Context, runtimeID int64) error {
	if a == nil || a.manager == nil {
		return ErrProxyRuntimeInvalid
	}
	return a.manager.Stop(ctx, runtimeID)
}

func (a *ProxyRuntimeAdmin) Create(ctx context.Context, request service.ProxyRuntimeCreateRequest) (*service.ProxyRuntimeCreated, error) {
	if a == nil || a.repository == nil || a.manager == nil || a.keyring == nil || !a.manager.enabled {
		return nil, ErrProxyRuntimeInvalid
	}
	payload, source, err := a.resolveRuntimeInput(ctx, request.Input)
	if err != nil {
		return nil, err
	}
	share, jsonNodes, err := parseRuntimePayload(payload)
	if err != nil {
		return nil, err
	}
	var canonical []byte
	var candidateName string
	for _, candidate := range share {
		if candidate.Fingerprint == request.Fingerprint {
			canonical = append([]byte(nil), candidate.Outbound...)
			candidateName = candidate.Name
			break
		}
	}
	if canonical == nil {
		for _, candidate := range jsonNodes {
			if candidate.Fingerprint == request.Fingerprint {
				canonical, err = proxyimport.EncodeCanonicalCandidate(candidate)
				candidateName = candidate.Name
				break
			}
		}
	}
	if err != nil || canonical == nil {
		return nil, ErrProxyRuntimeInvalid
	}
	encrypted, err := a.keyring.Encrypt("config", canonical)
	clear(canonical)
	if err != nil {
		return nil, fmt.Errorf("encrypt native proxy runtime config: %w", err)
	}
	username, err := randomRuntimeCredential(18)
	if err != nil {
		return nil, err
	}
	password, err := randomRuntimeCredential(32)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(request.Name)
	if name == "" {
		name = candidateName
	}
	result, err := a.repository.CreateBatch(ctx, ProxyRuntimeBatchInput{OwnerUserID: request.OwnerUserID, Source: source, Runtimes: []ProxyRuntimeCreateInput{{
		Name: name, Visibility: request.Visibility,
		NormalizedConfigEncrypted: encrypted, EncryptionVersion: 1,
		NodeFingerprint: request.Fingerprint, ListenHost: "127.0.0.1", ListenPort: 0,
		ListenUsername: username, ListenPassword: password,
		FallbackMode: request.FallbackMode, BackupProxyID: request.BackupProxyID,
	}}})
	if err != nil {
		return nil, err
	}
	created := result.Items[0]
	if err := a.manager.Start(ctx, created.RuntimeID); err != nil {
		return &service.ProxyRuntimeCreated{ProxyID: created.ProxyID, RuntimeID: created.RuntimeID, Status: "error"}, fmt.Errorf("native proxy created but failed to start: %w", err)
	}
	status, err := a.repository.GetRuntimeStatusByProxyID(ctx, created.ProxyID)
	if err != nil {
		return &service.ProxyRuntimeCreated{ProxyID: created.ProxyID, RuntimeID: created.RuntimeID, Status: "unknown"}, nil
	}
	return &service.ProxyRuntimeCreated{ProxyID: created.ProxyID, RuntimeID: created.RuntimeID, Status: status.Status}, nil
}

// Listener ports are allocated inside CreateBatch's transaction under a
// PostgreSQL advisory transaction lock; preview/create never reserves ports.

func (a *ProxyRuntimeAdmin) resolveRuntimeInput(ctx context.Context, input string) (string, *ProxyRuntimeSourceInput, error) {
	trimmed := strings.TrimSpace(input)
	if strings.HasPrefix(strings.ToLower(trimmed), "https://") && !strings.Contains(trimmed, "\n") {
		if a.fetcher == nil || a.keyring == nil {
			return "", nil, ErrProxyRuntimeInvalid
		}
		fetched, err := a.fetcher.Fetch(ctx, ProxySubscriptionFetchRequest{URL: trimmed})
		if err != nil || fetched.NotModified {
			return "", nil, fmt.Errorf("fetch native proxy subscription: %w", err)
		}
		encryptedURL, err := a.keyring.Encrypt("source", []byte(trimmed))
		if err != nil {
			return "", nil, fmt.Errorf("encrypt native proxy subscription URL: %w", err)
		}
		source := &ProxyRuntimeSourceInput{
			Name: "subscription", SourceType: "singbox_subscription",
			SourceSecretEncrypted: encryptedURL, EncryptionVersion: 1,
			RefreshIntervalMinutes: 60,
			ETag:                   fetched.ETag, LastModified: fetched.LastModified,
		}
		return string(fetched.Body), source, nil
	}
	return trimmed, nil, nil
}

func parseRuntimePayload(input string) ([]proxyimport.Result, []proxyimport.JSONCandidate, error) {
	input = strings.TrimSpace(input)
	if input == "" || len(input) > 2<<20 {
		return nil, nil, proxyimport.ErrInvalidInput
	}
	if strings.Contains(input, "://") && !strings.Contains(input, "\n") {
		candidate, err := proxyimport.ParseShareLink(input)
		if err == nil {
			return []proxyimport.Result{*candidate}, nil, nil
		}
	}
	parsed, err := proxyimport.ParseSubscription([]byte(input))
	if err != nil {
		return nil, nil, err
	}
	return parsed.Candidates, parsed.JSONNodes, nil
}

func randomRuntimeCredential(bytesCount int) (string, error) {
	buffer := make([]byte, bytesCount)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate runtime listener credential: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
