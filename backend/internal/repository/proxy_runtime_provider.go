package repository

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/proxyruntime"
)

func ProvideProxyRuntimeManager(cfg *config.Config, client *ent.Client, repo *ProxyRuntimeRepository) (*ProxyRuntimeManager, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	if !cfg.NativeProxyRuntime.Enabled {
		ctx, cancel := context.WithCancel(context.Background())
		return &ProxyRuntimeManager{enabled: false, ctx: ctx, cancel: cancel, items: make(map[int64]*managedProxyRuntime)}, nil
	}
	keyring, err := LoadProxyRuntimeKeyring(context.Background(), client)
	if err != nil {
		return nil, err
	}
	dataDir := cfg.NativeProxyRuntime.DataDir
	if !filepath.IsAbs(dataDir) {
		absolute, absErr := filepath.Abs(dataDir)
		if absErr != nil {
			return nil, fmt.Errorf("resolve native proxy runtime data directory: %w", absErr)
		}
		dataDir = absolute
	}
	options := ProxyRuntimeManagerOptions{
		Enabled:       cfg.NativeProxyRuntime.Enabled,
		BinaryPath:    cfg.NativeProxyRuntime.BinaryPath,
		DataDir:       dataDir,
		ReadyTimeout:  time.Duration(cfg.NativeProxyRuntime.ReadyTimeoutSeconds) * time.Second,
		ProbeInterval: time.Duration(cfg.NativeProxyRuntime.ProbeIntervalMillis) * time.Millisecond,
		StopTimeout:   time.Duration(cfg.NativeProxyRuntime.StopTimeoutSeconds) * time.Second,
		RestartPolicy: proxyruntime.RestartPolicy{
			MaxRestarts: cfg.NativeProxyRuntime.MaxRestarts,
			BaseDelay:   time.Duration(cfg.NativeProxyRuntime.RestartBaseSeconds) * time.Second,
			MaxDelay:    time.Duration(cfg.NativeProxyRuntime.RestartMaxSeconds) * time.Second,
		},
	}
	manager, err := NewProxyRuntimeManager(repo, keyring, options)
	if err != nil {
		return nil, err
	}
	if err := manager.Recover(context.Background()); err != nil {
		return nil, fmt.Errorf("recover native proxy runtimes: %w", err)
	}
	return manager, nil
}
