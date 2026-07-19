package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

type runtimeExitProberStub struct {
	info *service.ProxyExitInfo
	err  error
}

func (s runtimeExitProberStub) ProbeProxy(context.Context, string) (*service.ProxyExitInfo, int64, error) {
	return s.info, 10, s.err
}

func TestRuntimeQualityGateRequiresExitProbe(t *testing.T) {
	gate := &runtimeQualityGate{exitProber: runtimeExitProberStub{err: errors.New("blocked")}}
	_, err := gate.Check(context.Background(), "socks5h://user:password@127.0.0.1:21000")
	if err == nil {
		t.Fatal("failed exit probe accepted")
	}
}

func TestRuntimeQualityGateRejectsMissingDependencies(t *testing.T) {
	var gate *runtimeQualityGate
	if _, err := gate.Check(context.Background(), ""); err == nil {
		t.Fatal("nil quality gate accepted")
	}
}
