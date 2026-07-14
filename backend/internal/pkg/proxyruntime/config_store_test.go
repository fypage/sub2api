package proxyruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type checkerFunc func(context.Context, string) error

func (f checkerFunc) Check(ctx context.Context, path string) error { return f(ctx, path) }

func TestConfigStoreValidatesThenAtomicallyCommits(t *testing.T) {
	dataDir := t.TempDir()
	checked := ""
	store := ConfigStore{DataDir: dataDir, Checker: checkerFunc(func(_ context.Context, path string) error {
		checked = path
		data, err := os.ReadFile(path)
		if err != nil || string(data) != `{"ok":true}` {
			t.Fatalf("checker received invalid temporary config: %q %v", data, err)
		}
		return nil
	})}
	finalPath, err := store.ValidateAndCommit(context.Background(), 42, []byte(`{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(dataDir, "proxy-runtimes", "42", "config.json")
	if finalPath != expected || checked == finalPath || filepath.Dir(checked) != filepath.Dir(finalPath) {
		t.Fatalf("unexpected paths: checked=%s final=%s", checked, finalPath)
	}
	data, err := os.ReadFile(finalPath)
	if err != nil || string(data) != `{"ok":true}` {
		t.Fatalf("committed config mismatch: %q %v", data, err)
	}
	info, err := os.Stat(finalPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("config permissions: %v %v", info, err)
	}
	dirInfo, err := os.Stat(filepath.Dir(finalPath))
	if err != nil || dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("directory permissions: %v %v", dirInfo, err)
	}
}

func TestConfigStoreCheckFailurePreservesOldConfig(t *testing.T) {
	dataDir := t.TempDir()
	runtimeDir := filepath.Join(dataDir, "proxy-runtimes", "7")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	finalPath := filepath.Join(runtimeDir, "config.json")
	if err := os.WriteFile(finalPath, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	store := ConfigStore{DataDir: dataDir, Checker: checkerFunc(func(context.Context, string) error { return ErrConfigCheckFailed })}
	path, err := store.ValidateAndCommit(context.Background(), 7, []byte("new-secret"))
	if !errors.Is(err, ErrConfigCheckFailed) || path != "" {
		t.Fatalf("unexpected check result: %q %v", path, err)
	}
	data, readErr := os.ReadFile(finalPath)
	if readErr != nil || string(data) != "old" {
		t.Fatalf("old config was replaced: %q %v", data, readErr)
	}
	matches, globErr := filepath.Glob(filepath.Join(runtimeDir, ".config-*.tmp"))
	if globErr != nil || len(matches) != 0 {
		t.Fatalf("temporary secret files remain: %v %v", matches, globErr)
	}
}

func TestConfigStoreRejectsSymlinks(t *testing.T) {
	dataDir := t.TempDir()
	target := t.TempDir()
	root := filepath.Join(dataDir, "proxy-runtimes")
	if err := os.Symlink(target, root); err != nil {
		t.Fatal(err)
	}
	store := ConfigStore{DataDir: dataDir, Checker: checkerFunc(func(context.Context, string) error { return nil })}
	if _, err := store.ValidateAndCommit(context.Background(), 1, []byte("secret")); !errors.Is(err, ErrInvalidConfigStoreInput) {
		t.Fatalf("symlink root accepted: %v", err)
	}

	dataDir2 := t.TempDir()
	runtimeDir := filepath.Join(dataDir2, "proxy-runtimes", "1")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(runtimeDir, "config.json")); err != nil {
		t.Fatal(err)
	}
	store.DataDir = dataDir2
	if _, err := store.ValidateAndCommit(context.Background(), 1, []byte("secret")); !errors.Is(err, ErrInvalidConfigStoreInput) {
		t.Fatalf("symlink target accepted: %v", err)
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "outside" {
		t.Fatalf("outside target modified: %q %v", data, err)
	}
}

func TestConfigStoreRejectsInvalidInputsBeforeChecker(t *testing.T) {
	calls := 0
	store := ConfigStore{DataDir: "relative", Checker: checkerFunc(func(context.Context, string) error { calls++; return nil })}
	cases := []struct {
		id     int64
		config []byte
	}{{0, []byte("x")}, {1, nil}, {1, []byte("x")}}
	for _, item := range cases {
		if _, err := store.ValidateAndCommit(context.Background(), item.id, item.config); !errors.Is(err, ErrInvalidConfigStoreInput) {
			t.Fatalf("invalid input accepted: %+v %v", item, err)
		}
	}
	store.DataDir = t.TempDir()
	if _, err := store.ValidateAndCommit(context.Background(), 1, []byte(strings.Repeat("x", (4<<20)+1))); !errors.Is(err, ErrInvalidConfigStoreInput) {
		t.Fatalf("oversized config accepted: %v", err)
	}
	if calls != 0 {
		t.Fatalf("checker called for invalid input: %d", calls)
	}
}

func TestSingBoxCheckerRejectsInvalidBinaryAndHidesCommandOutput(t *testing.T) {
	if err := (SingBoxChecker{BinaryPath: "relative"}).Check(context.Background(), "/tmp/config"); !errors.Is(err, ErrInvalidConfigStoreInput) {
		t.Fatalf("relative binary accepted: %v", err)
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "sing-box")
	script := "#!/bin/sh\necho secret-output >&2\nexit 1\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(config, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	err := (SingBoxChecker{BinaryPath: binary}).Check(context.Background(), config)
	if !errors.Is(err, ErrConfigCheckFailed) || strings.Contains(err.Error(), "secret-output") {
		t.Fatalf("checker leaked output or wrong error: %v", err)
	}
}
