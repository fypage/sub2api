package repository

import (
	"context"
	"fmt"

	"github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/config"
)

func ProvideProxySubscriptionRefresher(cfg *config.Config, client *ent.Client, repo *ProxyRuntimeRepository, manager *ProxyRuntimeManager, fetcher *ProxySubscriptionFetcher) (*ProxySubscriptionRefresher, error) {
	if cfg == nil || !cfg.NativeProxyRuntime.Enabled {
		return &ProxySubscriptionRefresher{}, nil
	}
	keyring, err := LoadProxyRuntimeKeyring(context.Background(), client)
	if err != nil {
		return nil, fmt.Errorf("load proxy subscription refresher keyring: %w", err)
	}
	refresher := NewProxySubscriptionRefresher(repo, manager, fetcher, keyring)
	refresher.Start()
	return refresher, nil
}
