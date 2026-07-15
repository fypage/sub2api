package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/proxyruntime"
)

type fakeRuntimeProcess struct {
	pid     int64
	done    chan struct{}
	waitErr error
	stopped bool
}

func (p *fakeRuntimeProcess) PID() int64 { return p.pid }
func (p *fakeRuntimeProcess) Wait(ctx context.Context) error {
	select {
	case <-p.done:
		return p.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *fakeRuntimeProcess) Stop(context.Context) error {
	p.stopped = true
	select {
	case <-p.done:
	default:
		close(p.done)
	}
	return nil
}

type fakeRuntimeStarter struct {
	processes []*fakeRuntimeProcess
	configs   []proxyruntime.ProcessConfig
	err       error
}

func (s *fakeRuntimeStarter) Start(_ context.Context, config proxyruntime.ProcessConfig) (runtimeProcess, error) {
	s.configs = append(s.configs, config)
	if s.err != nil {
		return nil, s.err
	}
	process := &fakeRuntimeProcess{pid: int64(1000 + len(s.processes)), done: make(chan struct{})}
	s.processes = append(s.processes, process)
	return process, nil
}

func TestDisabledProxyRuntimeManagerDoesNothing(t *testing.T) {
	manager := &ProxyRuntimeManager{enabled: false}
	if err := manager.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background(), 1); !errors.Is(err, ErrProxyRuntimeInvalid) {
		t.Fatalf("disabled manager accepted start: %v", err)
	}
	if err := manager.StopAll(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestStableRuntimeErrorsNeverExposeUnderlyingMessage(t *testing.T) {
	secret := errors.New("password=super-secret")
	if got := stableRuntimeError(secret); got != "runtime_start_failed" {
		t.Fatalf("secret-bearing error was exposed: %q", got)
	}
	cases := []struct {
		err  error
		code string
	}{
		{proxyruntime.ErrListenerInUse, "listener_in_use"},
		{proxyruntime.ErrListenerNotReady, "listener_not_ready"},
		{proxyruntime.ErrProcessExitedEarly, "process_exit"},
		{proxyruntime.ErrConfigCheckFailed, "config_check_failed"},
	}
	for _, item := range cases {
		if got := runtimeFailureCode(item.err); got != item.code {
			t.Fatalf("error %v classified as %s", item.err, got)
		}
	}
}

func TestFakeRuntimeStarterSupportsShutdownContract(t *testing.T) {
	starter := &fakeRuntimeStarter{}
	process, err := starter.Start(context.Background(), proxyruntime.ProcessConfig{StopTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if process.PID() <= 0 {
		t.Fatal("fake process missing pid")
	}
	if err := process.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}
