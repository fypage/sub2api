package proxyruntime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestManagedProcessBecomesReadyAndStops(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture requires unix")
	}
	dir := t.TempDir()
	port := reservePort(t)
	binary := writeFixture(t, dir, fmt.Sprintf("#!/bin/sh\nexec python3 -m http.server %d --bind 127.0.0.1\n", port))
	config := writeConfig(t, dir)
	process, err := StartManagedProcess(context.Background(), ProcessConfig{
		BinaryPath: binary, ConfigPath: config, ListenHost: "127.0.0.1", ListenPort: port,
		ReadyTimeout: 5 * time.Second, ProbeInterval: 50 * time.Millisecond, StopTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if process.PID() <= 0 {
		t.Fatal("missing managed pid")
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := process.Stop(stopCtx); err != nil {
		t.Fatalf("graceful stop failed: %v", err)
	}
	if err := process.Wait(context.Background()); err == nil {
		t.Fatal("signal-terminated fixture should report its wait result")
	}
}

func TestManagedProcessReportsEarlyExitWithoutOutputLeak(t *testing.T) {
	dir := t.TempDir()
	binary := writeFixture(t, dir, "#!/bin/sh\necho secret-node-credential >&2\nexit 7\n")
	config := writeConfig(t, dir)
	_, err := StartManagedProcess(context.Background(), ProcessConfig{
		BinaryPath: binary, ConfigPath: config, ListenHost: "127.0.0.1", ListenPort: reservePort(t),
		ReadyTimeout: 2 * time.Second, ProbeInterval: 25 * time.Millisecond, StopTimeout: time.Second,
	})
	if !errors.Is(err, ErrProcessExitedEarly) || err.Error() == "secret-node-credential" {
		t.Fatalf("unexpected early exit error: %v", err)
	}
}

func TestManagedProcessReadyTimeoutReapsChild(t *testing.T) {
	dir := t.TempDir()
	binary := writeFixture(t, dir, "#!/bin/sh\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n")
	config := writeConfig(t, dir)
	started := time.Now()
	_, err := StartManagedProcess(context.Background(), ProcessConfig{
		BinaryPath: binary, ConfigPath: config, ListenHost: "127.0.0.1", ListenPort: reservePort(t),
		ReadyTimeout: time.Second, ProbeInterval: 25 * time.Millisecond, StopTimeout: time.Second,
	})
	if !errors.Is(err, ErrListenerNotReady) || time.Since(started) > 4*time.Second {
		t.Fatalf("timeout did not stop promptly: %v", err)
	}
}

func TestManagedProcessRejectsOccupiedListener(t *testing.T) {
	dir := t.TempDir()
	binary := writeFixture(t, dir, "#!/bin/sh\nexit 0\n")
	config := writeConfig(t, dir)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := listener.Addr().(*net.TCPAddr).Port
	_, err = StartManagedProcess(context.Background(), ProcessConfig{
		BinaryPath: binary, ConfigPath: config, ListenHost: "127.0.0.1", ListenPort: port,
		ReadyTimeout: time.Second, ProbeInterval: 25 * time.Millisecond, StopTimeout: time.Second,
	})
	if !errors.Is(err, ErrListenerInUse) {
		t.Fatalf("occupied listener accepted: %v", err)
	}
}

func TestManagedProcessRejectsUnsafeConfiguration(t *testing.T) {
	dir := t.TempDir()
	binary := writeFixture(t, dir, "#!/bin/sh\nexit 0\n")
	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(config, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := StartManagedProcess(context.Background(), ProcessConfig{
		BinaryPath: binary, ConfigPath: config, ListenHost: "0.0.0.0", ListenPort: 1,
		ReadyTimeout: time.Second, ProbeInterval: 25 * time.Millisecond, StopTimeout: time.Second,
	})
	if !errors.Is(err, ErrInvalidProcessConfig) {
		t.Fatalf("unsafe config accepted: %v", err)
	}
}

func TestRestartPolicyIsBounded(t *testing.T) {
	policy := RestartPolicy{MaxRestarts: 4, BaseDelay: time.Second, MaxDelay: 3 * time.Second}
	expected := []time.Duration{time.Second, 2 * time.Second, 3 * time.Second, 3 * time.Second}
	for attempt, want := range expected {
		got, ok := policy.Delay(attempt)
		if !ok || got != want {
			t.Fatalf("attempt %d: got %v %v want %v", attempt, got, ok, want)
		}
	}
	if _, ok := policy.Delay(4); ok {
		t.Fatal("restart budget exceeded")
	}
}

func reservePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func writeFixture(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "sing-box-fixture")
	if err := os.WriteFile(path, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"listen_port":`+strconv.Itoa(reservePort(t))+`}`), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
