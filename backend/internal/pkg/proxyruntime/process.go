package proxyruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

var (
	ErrInvalidProcessConfig = errors.New("invalid proxy runtime process configuration")
	ErrProcessExitedEarly   = errors.New("sing-box process exited before listener became ready")
	ErrListenerInUse        = errors.New("sing-box listener address is already in use")
	ErrListenerNotReady     = errors.New("sing-box listener did not become ready")
	ErrProcessStopTimeout   = errors.New("sing-box process required forced termination")
)

type ProcessConfig struct {
	BinaryPath    string
	ConfigPath    string
	ListenHost    string
	ListenPort    int
	ReadyTimeout  time.Duration
	ProbeInterval time.Duration
	StopTimeout   time.Duration
}

type ManagedProcess struct {
	cmd         *exec.Cmd
	listenAddr  string
	stopTimeout time.Duration
	done        chan struct{}
	mu          sync.Mutex
	waitErr     error
}

func StartManagedProcess(ctx context.Context, config ProcessConfig) (*ManagedProcess, error) {
	if err := validateProcessConfig(config); err != nil {
		return nil, err
	}
	listenAddr := net.JoinHostPort(config.ListenHost, strconv.Itoa(config.ListenPort))
	available, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, ErrListenerInUse
	}
	if err := available.Close(); err != nil {
		return nil, fmt.Errorf("release listener availability probe: %w", err)
	}
	command := exec.Command(config.BinaryPath, "run", "-c", config.ConfigPath)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.Stdin = nil
	command.Dir = filepath.Dir(config.ConfigPath)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + command.Dir}
	configureProcessGroup(command)
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start sing-box process: %w", err)
	}
	process := &ManagedProcess{
		cmd:         command,
		listenAddr:  listenAddr,
		stopTimeout: config.StopTimeout,
		done:        make(chan struct{}),
	}
	go process.reap()
	readyCtx, cancel := context.WithTimeout(ctx, config.ReadyTimeout)
	defer cancel()
	if err := process.waitReady(readyCtx, config.ProbeInterval); err != nil {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), config.StopTimeout+time.Second)
		_ = process.Stop(stopCtx)
		stopCancel()
		return nil, err
	}
	return process, nil
}

func (p *ManagedProcess) PID() int64 {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return int64(p.cmd.Process.Pid)
}

func (p *ManagedProcess) Wait(ctx context.Context) error {
	if p == nil || p.done == nil {
		return ErrInvalidProcessConfig
	}
	select {
	case <-p.done:
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *ManagedProcess) Stop(ctx context.Context) error {
	if p == nil || p.cmd == nil || p.cmd.Process == nil || p.done == nil {
		return ErrInvalidProcessConfig
	}
	select {
	case <-p.done:
		return nil
	default:
	}
	if err := signalProcessGroup(p.cmd, false); err != nil && !isProcessDone(err) {
		return fmt.Errorf("signal sing-box process: %w", err)
	}
	timer := time.NewTimer(p.stopTimeout)
	defer timer.Stop()
	select {
	case <-p.done:
		return nil
	case <-timer.C:
		if err := signalProcessGroup(p.cmd, true); err != nil && !isProcessDone(err) {
			return fmt.Errorf("kill sing-box process: %w", err)
		}
		select {
		case <-p.done:
			return ErrProcessStopTimeout
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *ManagedProcess) waitReady(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		connection, err := (&net.Dialer{Timeout: interval}).DialContext(ctx, "tcp", p.listenAddr)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		select {
		case <-p.done:
			return ErrProcessExitedEarly
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return ErrListenerNotReady
			}
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (p *ManagedProcess) reap() {
	err := p.cmd.Wait()
	p.mu.Lock()
	p.waitErr = err
	p.mu.Unlock()
	close(p.done)
}

func validateProcessConfig(config ProcessConfig) error {
	if !safeExecutable(config.BinaryPath) || !safeConfigFile(config.ConfigPath) {
		return ErrInvalidProcessConfig
	}
	if config.ListenHost != "127.0.0.1" && config.ListenHost != "::1" {
		return ErrInvalidProcessConfig
	}
	if config.ListenPort < 1 || config.ListenPort > 65535 {
		return ErrInvalidProcessConfig
	}
	if config.ReadyTimeout < time.Second || config.ReadyTimeout > 2*time.Minute ||
		config.ProbeInterval < 25*time.Millisecond || config.ProbeInterval > time.Second ||
		config.StopTimeout < time.Second || config.StopTimeout > 30*time.Second {
		return ErrInvalidProcessConfig
	}
	return nil
}

func safeExecutable(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0
}

func safeConfigFile(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&0077 == 0
}
