package proxyruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

var (
	ErrInvalidConfigStoreInput = errors.New("invalid proxy runtime config store input")
	ErrConfigCheckFailed       = errors.New("sing-box configuration check failed")
	ErrConfigCommitUncertain   = errors.New("proxy runtime config commit durability is uncertain")
)

type ConfigChecker interface {
	Check(ctx context.Context, configPath string) error
}

type SingBoxChecker struct {
	BinaryPath string
}

func (c SingBoxChecker) Check(ctx context.Context, configPath string) error {
	if !filepath.IsAbs(c.BinaryPath) || !filepath.IsAbs(configPath) {
		return ErrInvalidConfigStoreInput
	}
	info, err := os.Lstat(c.BinaryPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return fmt.Errorf("validate sing-box binary: %w", ErrInvalidConfigStoreInput)
	}
	command := exec.CommandContext(ctx, c.BinaryPath, "check", "-c", configPath)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return ErrConfigCheckFailed
	}
	return nil
}

type ConfigStore struct {
	DataDir string
	Checker ConfigChecker
}

func (s ConfigStore) ValidateAndCommit(ctx context.Context, runtimeID int64, config []byte) (string, error) {
	if runtimeID <= 0 || len(config) == 0 || len(config) > 4<<20 || s.Checker == nil || !filepath.IsAbs(s.DataDir) {
		return "", ErrInvalidConfigStoreInput
	}
	root := filepath.Join(filepath.Clean(s.DataDir), "proxy-runtimes")
	runtimeDir := filepath.Join(root, strconv.FormatInt(runtimeID, 10))
	if err := ensurePrivateDirectory(root); err != nil {
		return "", err
	}
	if err := ensurePrivateDirectory(runtimeDir); err != nil {
		return "", err
	}

	temporary, err := os.CreateTemp(runtimeDir, ".config-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create runtime config temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0600); err != nil {
		return "", fmt.Errorf("set runtime config permissions: %w", err)
	}
	if _, err := temporary.Write(config); err != nil {
		return "", fmt.Errorf("write runtime config: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return "", fmt.Errorf("sync runtime config: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close runtime config: %w", err)
	}
	if err := s.Checker.Check(ctx, temporaryPath); err != nil {
		return "", err
	}

	finalPath := filepath.Join(runtimeDir, "config.json")
	if info, err := os.Lstat(finalPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("runtime config target is symlink: %w", ErrInvalidConfigStoreInput)
	} else if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("inspect runtime config target: %w", err)
	}
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		return "", fmt.Errorf("commit runtime config: %w", err)
	}
	committed = true
	if err := syncDirectory(runtimeDir); err != nil {
		return finalPath, fmt.Errorf("%w: %v", ErrConfigCommitUncertain, err)
	}
	return finalPath, nil
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0700); err != nil {
			return fmt.Errorf("create runtime directory: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect runtime directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("runtime directory is unsafe: %w", ErrInvalidConfigStoreInput)
	}
	if err := os.Chmod(path, 0700); err != nil {
		return fmt.Errorf("set runtime directory permissions: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open runtime directory for sync: %w", err)
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync runtime directory: %w", err)
	}
	return nil
}

// check output is intentionally discarded to avoid leaking node credentials.
