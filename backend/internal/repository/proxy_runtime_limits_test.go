package repository

import (
	"errors"
	"testing"
)

func TestProxyRuntimeManagerInstanceLimits(t *testing.T) {
	owner := int64(7)
	other := int64(8)
	manager := &ProxyRuntimeManager{
		maxInstances: 2,
		maxPerUser:   1,
		items: map[int64]*managedProxyRuntime{
			1: {proxyID: 101, ownerUserID: &owner},
		},
	}
	if err := manager.reserveInstance(&owner); !errors.Is(err, ErrProxyRuntimeUserLimit) {
		t.Fatalf("expected per-user reservation limit, got %v", err)
	}
	if err := manager.reserveInstance(&other); err != nil {
		t.Fatalf("different user should fit global limit: %v", err)
	}
	manager.releaseReservation(&other)
	manager.items[2] = &managedProxyRuntime{proxyID: 102, ownerUserID: &other}
	if err := manager.reserveInstance(nil); !errors.Is(err, ErrProxyRuntimeInstanceLimit) {
		t.Fatalf("expected global reservation limit, got %v", err)
	}
}

func TestProxyRuntimeManagerDefaultInstanceLimits(t *testing.T) {
	manager := &ProxyRuntimeManager{maxInstances: 64, maxPerUser: 16}
	if err := manager.checkInstanceLimit(nil); err != nil {
		t.Fatalf("empty manager unexpectedly limited: %v", err)
	}
}
