package repository

import (
	"context"
	"fmt"

	"github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/config"
)

func ProvideProxyRuntimeAdmin(cfg *config.Config, client *ent.Client, repo *ProxyRuntimeRepository, manager *ProxyRuntimeManager, fetcher *ProxySubscriptionFetcher) (*ProxyRuntimeAdmin, error) {
	if cfg == nil || !cfg.NativeProxyRuntime.Enabled {
		return &ProxyRuntimeAdmin{repository: repo, manager: manager}, nil
	}
	keyring, err := LoadProxyRuntimeKeyring(context.Background(), client)
	if err != nil {
		return nil, fmt.Errorf("load native proxy runtime admin keyring: %w", err)
	}
	return NewProxyRuntimeAdmin(repo, manager, keyring, fetcher), nil
}
