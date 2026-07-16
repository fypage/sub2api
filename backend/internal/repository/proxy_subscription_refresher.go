package repository

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/runtimecrypto"
)

type ProxySubscriptionRefresher struct {
	repo    *ProxyRuntimeRepository
	manager *ProxyRuntimeManager
	fetcher *ProxySubscriptionFetcher
	keyring *runtimecrypto.Keyring

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewProxySubscriptionRefresher(repo *ProxyRuntimeRepository, manager *ProxyRuntimeManager, fetcher *ProxySubscriptionFetcher, keyring *runtimecrypto.Keyring) *ProxySubscriptionRefresher {
	ctx, cancel := context.WithCancel(context.Background())
	return &ProxySubscriptionRefresher{repo: repo, manager: manager, fetcher: fetcher, keyring: keyring, ctx: ctx, cancel: cancel}
}

func (r *ProxySubscriptionRefresher) Start() {
	if r == nil || r.repo == nil || r.manager == nil || r.fetcher == nil || r.keyring == nil || !r.manager.enabled {
		return
	}
	r.wg.Add(1)
	go r.loop()
}

func (r *ProxySubscriptionRefresher) Stop(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if r.cancel != nil {
		r.cancel()
	}
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *ProxySubscriptionRefresher) loop() {
	defer r.wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if err := r.RefreshDue(r.ctx); err != nil && r.ctx.Err() == nil {
			slog.Warn("native proxy subscription refresh cycle failed", "error", "subscription_refresh_failed")
		}
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *ProxySubscriptionRefresher) RefreshDue(ctx context.Context) error {
	candidates, err := r.repo.ListDueSubscriptionSources(ctx, 100)
	if err != nil {
		return err
	}
	for _, source := range candidates {
		if err := r.refreshOne(ctx, source); err != nil {
			_ = r.repo.RecordSubscriptionSync(context.Background(), source.SourceID, "failed", "", "", "subscription_refresh_failed", "subscription refresh failed")
		}
	}
	return nil
}

func (r *ProxySubscriptionRefresher) refreshOne(ctx context.Context, source ProxySubscriptionRefreshCandidate) error {
	lease, acquired, err := r.repo.TryAcquireSubscriptionRefreshLease(ctx, source.SourceID)
	if err != nil {
		return err
	}
	if !acquired {
		return nil
	}
	defer lease.Release()
	plain, err := r.keyring.Decrypt("source", source.SourceSecretEncrypted)
	if err != nil {
		return fmt.Errorf("decrypt subscription source: %w", err)
	}
	url := string(plain)
	clear(plain)
	fetched, err := r.fetcher.Fetch(ctx, ProxySubscriptionFetchRequest{URL: url, ETag: source.ETag, LastModified: source.LastModified})
	if err != nil {
		return err
	}
	if fetched.NotModified {
		return r.repo.RecordSubscriptionSync(ctx, source.SourceID, "success", source.ETag, source.LastModified, "", "")
	}
	share, nodes, err := parseRuntimePayload(string(fetched.Body))
	clear(fetched.Body)
	if err != nil {
		return err
	}
	present := make(map[string]bool, len(share)+len(nodes))
	for _, candidate := range share {
		present[candidate.Fingerprint] = true
	}
	for _, candidate := range nodes {
		present[candidate.Fingerprint] = true
	}
	runtimes, err := r.repo.ListSourceRuntimes(ctx, source.SourceID)
	if err != nil {
		return err
	}
	removed := 0
	for _, runtime := range runtimes {
		if present[runtime.Fingerprint] {
			continue
		}
		status, statusErr := r.repo.GetRuntimeStatusByProxyID(ctx, runtime.ProxyID)
		if statusErr == nil && status != nil && status.Status != "stopped" {
			if err := r.manager.Stop(ctx, runtime.RuntimeID); err != nil {
				// Another application replica may own the runtime lease. Do not
				// race its process by mutating state; retry this source later.
				continue
			}
		}
		if err := r.repo.MarkSubscriptionRuntimeRemoved(ctx, runtime.RuntimeID); err != nil {
			return err
		}
		removed++
	}
	status := "success"
	if removed > 0 {
		status = "partial"
	}
	return r.repo.RecordSubscriptionSync(ctx, source.SourceID, status, fetched.ETag, fetched.LastModified, "", "")
}

// New subscription nodes are intentionally not auto-created during refresh.
