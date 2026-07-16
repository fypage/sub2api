package repository

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/proxyimport"
	"github.com/Wei-Shaw/sub2api/internal/pkg/proxyruntime"
	"github.com/Wei-Shaw/sub2api/internal/pkg/runtimecrypto"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

var (
	ErrProxyRuntimeAlreadyManaged = errors.New("native proxy runtime is already managed locally")
	ErrProxyRuntimeLeaseBusy      = errors.New("native proxy runtime is managed by another instance")
)

type runtimeProcess interface {
	PID() int64
	Wait(context.Context) error
	Stop(context.Context) error
}

type runtimeProcessStarter interface {
	Start(context.Context, proxyruntime.ProcessConfig) (runtimeProcess, error)
}

type nativeProcessStarter struct{}

func (nativeProcessStarter) Start(ctx context.Context, config proxyruntime.ProcessConfig) (runtimeProcess, error) {
	return proxyruntime.StartManagedProcess(ctx, config)
}

type managedProxyRuntime struct {
	lease      *ProxyRuntimeLease
	process    runtimeProcess
	configPath string
	processCfg proxyruntime.ProcessConfig
	proxyID    int64
	proxyURL   string
	stopping   bool
	mu         sync.Mutex
}

type ProxyRuntimeManager struct {
	enabled       bool
	repository    *ProxyRuntimeRepository
	keyring       *runtimecrypto.Keyring
	store         proxyruntime.ConfigStore
	starter       runtimeProcessStarter
	policy        proxyruntime.RestartPolicy
	qualityGate   RuntimeQualityGate
	binaryPath    string
	readyTimeout  time.Duration
	probeInterval time.Duration
	stopTimeout   time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	items  map[int64]*managedProxyRuntime
	wg     sync.WaitGroup
}

type RuntimeQualityResult struct {
	Status      string
	Score       int
	ExitIP      string
	CountryCode string
	ErrorCode   string
	ErrorText   string
}

type RuntimeQualityGate interface {
	Check(ctx context.Context, proxyURL string) (RuntimeQualityResult, error)
}

type ProxyRuntimeManagerOptions struct {
	Enabled       bool
	BinaryPath    string
	DataDir       string
	ReadyTimeout  time.Duration
	ProbeInterval time.Duration
	StopTimeout   time.Duration
	RestartPolicy proxyruntime.RestartPolicy
}

func NewProxyRuntimeManager(repo *ProxyRuntimeRepository, keyring *runtimecrypto.Keyring, qualityGate RuntimeQualityGate, options ProxyRuntimeManagerOptions) (*ProxyRuntimeManager, error) {
	if repo == nil || keyring == nil || qualityGate == nil {
		return nil, fmt.Errorf("proxy runtime repository and keyring are required")
	}
	checker := proxyruntime.SingBoxChecker{BinaryPath: options.BinaryPath}
	if options.ReadyTimeout <= 0 {
		options.ReadyTimeout = 20 * time.Second
	}
	if options.ProbeInterval <= 0 {
		options.ProbeInterval = 100 * time.Millisecond
	}
	if options.StopTimeout <= 0 {
		options.StopTimeout = 5 * time.Second
	}
	if options.RestartPolicy.MaxRestarts == 0 {
		options.RestartPolicy = proxyruntime.RestartPolicy{MaxRestarts: 5, BaseDelay: time.Second, MaxDelay: 30 * time.Second}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &ProxyRuntimeManager{
		enabled: options.Enabled, repository: repo, keyring: keyring,
		store:   proxyruntime.ConfigStore{DataDir: options.DataDir, Checker: checker},
		starter: nativeProcessStarter{}, policy: options.RestartPolicy, qualityGate: qualityGate,
		binaryPath: options.BinaryPath, readyTimeout: options.ReadyTimeout,
		probeInterval: options.ProbeInterval, stopTimeout: options.StopTimeout,
		ctx: ctx, cancel: cancel, items: make(map[int64]*managedProxyRuntime),
	}, nil
}

func (m *ProxyRuntimeManager) Recover(ctx context.Context) error {
	if m == nil || !m.enabled {
		return nil
	}
	ids, err := m.repository.ListAutoStartRuntimeIDs(ctx, 512)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := m.Start(ctx, id); err != nil && !errors.Is(err, ErrProxyRuntimeLeaseBusy) {
			// One corrupt or blocked node must not prevent the API server or other
			// runtimes from recovering. Start records a durable redacted error.
			slog.Warn("native proxy runtime recovery failed", "runtime_id", id, "error", stableRuntimeError(err))
		}
	}
	return nil
}

func (m *ProxyRuntimeManager) Start(ctx context.Context, runtimeID int64) error {
	if m == nil || !m.enabled || runtimeID <= 0 {
		return ErrProxyRuntimeInvalid
	}
	m.mu.Lock()
	if _, exists := m.items[runtimeID]; exists {
		m.mu.Unlock()
		return ErrProxyRuntimeAlreadyManaged
	}
	m.mu.Unlock()

	lease, acquired, err := m.repository.TryAcquireLifecycleLease(ctx, runtimeID)
	if err != nil {
		return err
	}
	if !acquired {
		return ErrProxyRuntimeLeaseBusy
	}
	started, err := m.startWithLease(ctx, lease)
	if err != nil {
		_ = lease.MarkFailed(context.Background(), runtimeFailureCode(err), stableRuntimeError(err), false)
		lease.Release()
		return err
	}
	m.mu.Lock()
	if _, exists := m.items[runtimeID]; exists {
		m.mu.Unlock()
		stopCtx, cancel := context.WithTimeout(context.Background(), started.processCfg.StopTimeout+time.Second)
		_ = started.process.Stop(stopCtx)
		cancel()
		lease.Release()
		return ErrProxyRuntimeAlreadyManaged
	}
	m.items[runtimeID] = started
	m.wg.Add(1)
	m.mu.Unlock()
	go m.supervise(runtimeID, started)
	return nil
}

func (m *ProxyRuntimeManager) startWithLease(ctx context.Context, lease *ProxyRuntimeLease) (*managedProxyRuntime, error) {
	snapshot, err := lease.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if !snapshot.AutoStart && snapshot.Status != "pending" {
		return nil, ErrProxyRuntimeStateConflict
	}
	if err := lease.MarkStarting(ctx); err != nil {
		return nil, err
	}
	canonical, err := m.keyring.Decrypt("config", snapshot.NormalizedConfigEncrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt native proxy runtime config: %w", err)
	}
	config, err := proxyimport.BuildCanonicalRuntimeConfig(canonical, proxyimport.RuntimeListener{
		Host: snapshot.ListenHost, Port: snapshot.ListenPort,
		Username: snapshot.ListenUsername, Password: snapshot.ListenPassword,
	})
	clear(canonical)
	if err != nil {
		return nil, fmt.Errorf("build native proxy runtime config: %w", err)
	}
	configPath, err := m.store.ValidateAndCommit(ctx, snapshot.ID, config)
	clear(config)
	if err != nil {
		return nil, err
	}
	processCfg := proxyruntime.ProcessConfig{
		BinaryPath: m.binaryPath, ConfigPath: configPath,
		ListenHost: snapshot.ListenHost, ListenPort: snapshot.ListenPort,
		ReadyTimeout: m.readyTimeout, ProbeInterval: m.probeInterval, StopTimeout: m.stopTimeout,
	}
	process, err := m.starter.Start(ctx, processCfg)
	if err != nil {
		return nil, err
	}
	if err := lease.MarkProcessReady(ctx, process.PID(), configPath); err != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), processCfg.StopTimeout+time.Second)
		_ = process.Stop(stopCtx)
		cancel()
		return nil, err
	}
	proxyURL := fmt.Sprintf("socks5h://%s:%s@%s", snapshot.ListenUsername, snapshot.ListenPassword,
		net.JoinHostPort(snapshot.ListenHost, strconv.Itoa(snapshot.ListenPort)))
	quality, err := m.qualityGate.Check(ctx, proxyURL)
	if err != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), processCfg.StopTimeout+time.Second)
		_ = process.Stop(stopCtx)
		cancel()
		return nil, fmt.Errorf("native proxy quality gate failed: %w", err)
	}
	if err := m.repository.UpdateQualityByProxyID(ctx, snapshot.ProxyID, service.ProxyRuntimeQualitySnapshot{
		Status: quality.Status, Score: quality.Score, ExitIP: quality.ExitIP,
		CountryCode: quality.CountryCode, ErrorCode: quality.ErrorCode, ErrorText: quality.ErrorText,
	}); err != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), processCfg.StopTimeout+time.Second)
		_ = process.Stop(stopCtx)
		cancel()
		return nil, err
	}
	return &managedProxyRuntime{lease: lease, process: process, configPath: configPath, processCfg: processCfg, proxyID: snapshot.ProxyID, proxyURL: proxyURL}, nil
}

func (m *ProxyRuntimeManager) supervise(runtimeID int64, item *managedProxyRuntime) {
	defer m.wg.Done()
	attempt := 0
	for {
		_ = item.process.Wait(m.ctx)
		item.mu.Lock()
		if item.stopping || m.ctx.Err() != nil {
			item.mu.Unlock()
			return
		}
		item.mu.Unlock()
		_ = item.lease.MarkFailed(context.Background(), "process_exit", "sing-box process exited unexpectedly", true)
		delay, retry := m.policy.Delay(attempt)
		if !retry {
			m.remove(runtimeID, item, true)
			return
		}
		attempt++
		timer := time.NewTimer(delay)
		select {
		case <-m.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if err := item.lease.MarkStarting(m.ctx); err != nil {
			m.remove(runtimeID, item, true)
			return
		}
		process, err := m.starter.Start(m.ctx, item.processCfg)
		if err != nil {
			_ = item.lease.MarkFailed(context.Background(), runtimeFailureCode(err), stableRuntimeError(err), true)
			continue
		}
		if err := item.lease.MarkProcessReady(m.ctx, process.PID(), item.configPath); err != nil {
			stopCtx, cancel := context.WithTimeout(context.Background(), item.processCfg.StopTimeout+time.Second)
			_ = process.Stop(stopCtx)
			cancel()
			m.remove(runtimeID, item, true)
			return
		}
		quality, err := m.qualityGate.Check(m.ctx, item.proxyURL)
		if err != nil {
			_ = item.lease.MarkFailed(context.Background(), "quality_gate_failed", "native proxy quality gate failed", true)
			_ = process.Stop(context.Background())
			continue
		}
		if err := m.repository.UpdateQualityByProxyID(m.ctx, item.proxyID, service.ProxyRuntimeQualitySnapshot{
			Status: quality.Status, Score: quality.Score, ExitIP: quality.ExitIP,
			CountryCode: quality.CountryCode, ErrorCode: quality.ErrorCode, ErrorText: quality.ErrorText,
		}); err != nil {
			_ = process.Stop(context.Background())
			m.remove(runtimeID, item, true)
			return
		}
		item.mu.Lock()
		item.process = process
		item.mu.Unlock()
	}
}

func (m *ProxyRuntimeManager) validateReplacementConfig(ctx context.Context, snapshot *ProxyRuntimeSnapshot, encrypted string) error {
	canonical, err := m.keyring.Decrypt("config", encrypted)
	if err != nil {
		return fmt.Errorf("decrypt replacement native proxy config: %w", err)
	}
	config, err := proxyimport.BuildCanonicalRuntimeConfig(canonical, proxyimport.RuntimeListener{
		Host: snapshot.ListenHost, Port: snapshot.ListenPort,
		Username: snapshot.ListenUsername, Password: snapshot.ListenPassword,
	})
	clear(canonical)
	if err != nil {
		return err
	}
	err = m.store.Validate(ctx, snapshot.ID, config)
	clear(config)
	return err
}

func (m *ProxyRuntimeManager) Reconfigure(ctx context.Context, runtimeID int64, encrypted, fingerprint, sourceNodeKey string) error {
	if m == nil || !m.enabled || runtimeID <= 0 {
		return ErrProxyRuntimeInvalid
	}
	m.mu.Lock()
	item, exists := m.items[runtimeID]
	m.mu.Unlock()
	if !exists {
		lease, acquired, err := m.repository.TryAcquireLifecycleLease(ctx, runtimeID)
		if err != nil {
			return err
		}
		if !acquired {
			return ErrProxyRuntimeLeaseBusy
		}
		snapshot, err := lease.Snapshot(ctx)
		if err != nil {
			lease.Release()
			return err
		}
		if err := m.validateReplacementConfig(ctx, snapshot, encrypted); err != nil {
			lease.Release()
			return err
		}
		if err := lease.UpdateConfig(ctx, encrypted, fingerprint, sourceNodeKey); err != nil {
			lease.Release()
			return err
		}
		if !snapshot.AutoStart {
			lease.Release()
			return nil
		}
		started, err := m.startWithLease(ctx, lease)
		if err != nil {
			_ = lease.MarkFailed(context.Background(), runtimeFailureCode(err), stableRuntimeError(err), false)
			lease.Release()
			return err
		}
		m.mu.Lock()
		m.items[runtimeID] = started
		m.wg.Add(1)
		m.mu.Unlock()
		go m.supervise(runtimeID, started)
		return nil
	}
	snapshot, err := item.lease.Snapshot(ctx)
	if err != nil {
		return err
	}
	if err := m.validateReplacementConfig(ctx, snapshot, encrypted); err != nil {
		return err
	}
	item.mu.Lock()
	item.stopping = true
	process := item.process
	item.mu.Unlock()
	if err := process.Stop(ctx); err != nil && !errors.Is(err, proxyruntime.ErrProcessStopTimeout) {
		item.mu.Lock()
		item.stopping = false
		item.mu.Unlock()
		return err
	}
	if err := item.lease.MarkStopped(ctx, true); err != nil {
		m.remove(runtimeID, item, true)
		return err
	}
	m.remove(runtimeID, item, false)
	if err := item.lease.UpdateConfig(ctx, encrypted, fingerprint, sourceNodeKey); err != nil {
		item.lease.Release()
		return err
	}
	started, err := m.startWithLease(ctx, item.lease)
	if err != nil {
		_ = item.lease.MarkFailed(context.Background(), runtimeFailureCode(err), stableRuntimeError(err), false)
		item.lease.Release()
		return err
	}
	m.mu.Lock()
	if _, conflict := m.items[runtimeID]; conflict {
		m.mu.Unlock()
		stopCtx, cancel := context.WithTimeout(context.Background(), started.processCfg.StopTimeout+time.Second)
		_ = started.process.Stop(stopCtx)
		cancel()
		item.lease.Release()
		return ErrProxyRuntimeAlreadyManaged
	}
	m.items[runtimeID] = started
	m.wg.Add(1)
	m.mu.Unlock()
	go m.supervise(runtimeID, started)
	return nil
}

func (m *ProxyRuntimeManager) Stop(ctx context.Context, runtimeID int64) error {
	return m.stop(ctx, runtimeID, false)
}

func (m *ProxyRuntimeManager) stop(ctx context.Context, runtimeID int64, autoStart bool) error {
	m.mu.Lock()
	item, exists := m.items[runtimeID]
	m.mu.Unlock()
	if !exists {
		return ErrProxyRuntimeNotFound
	}
	item.mu.Lock()
	item.stopping = true
	process := item.process
	item.mu.Unlock()
	err := process.Stop(ctx)
	stateErr := item.lease.MarkStopped(context.Background(), autoStart)
	m.remove(runtimeID, item, true)
	if err != nil && !errors.Is(err, proxyruntime.ErrProcessStopTimeout) {
		return err
	}
	return stateErr
}

func (m *ProxyRuntimeManager) StopAll(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Lock()
	ids := make([]int64, 0, len(m.items))
	for id := range m.items {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	var firstErr error
	for _, id := range ids {
		if err := m.stop(ctx, id, true); err != nil && !errors.Is(err, ErrProxyRuntimeNotFound) && firstErr == nil {
			firstErr = err
		}
	}
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		if firstErr == nil {
			firstErr = ctx.Err()
		}
	}
	return firstErr
}

func (m *ProxyRuntimeManager) remove(runtimeID int64, item *managedProxyRuntime, release bool) {
	m.mu.Lock()
	if current, exists := m.items[runtimeID]; exists && current == item {
		delete(m.items, runtimeID)
	}
	m.mu.Unlock()
	if release {
		item.lease.Release()
	}
}

func runtimeFailureCode(err error) string {
	switch {
	case errors.Is(err, proxyruntime.ErrListenerInUse):
		return "listener_in_use"
	case errors.Is(err, proxyruntime.ErrListenerNotReady):
		return "listener_not_ready"
	case errors.Is(err, proxyruntime.ErrProcessExitedEarly):
		return "process_exit"
	case errors.Is(err, proxyruntime.ErrConfigCheckFailed):
		return "config_check_failed"
	default:
		return "runtime_start_failed"
	}
}

func stableRuntimeError(err error) string {
	if err == nil {
		return "native proxy runtime operation failed"
	}
	return runtimeFailureCode(err)
}
