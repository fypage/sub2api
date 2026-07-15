package service

import (
	"context"
	"errors"
)

var ErrProxyRuntimeConflict = errors.New("native proxy runtime conflicts with an existing node or listener")

type ProxyRuntimePreview struct {
	Name         string `json:"name"`
	Protocol     string `json:"protocol"`
	ServerHint   string `json:"server_hint,omitempty"`
	Dependencies int    `json:"dependencies"`
	Fingerprint  string `json:"fingerprint"`
}

type ProxyRuntimeCreateRequest struct {
	Name          string
	OwnerUserID   *int64
	Input         string
	Fingerprint   string
	Visibility    string
	FallbackMode  string
	BackupProxyID *int64
}

type ProxyRuntimeCreated struct {
	ProxyID   int64
	RuntimeID int64
}

type ProxyRuntimeAdminService interface {
	Preview(input string) ([]ProxyRuntimePreview, error)
	Create(ctx context.Context, request ProxyRuntimeCreateRequest) (*ProxyRuntimeCreated, error)
	Start(ctx context.Context, runtimeID int64) error
	Stop(ctx context.Context, runtimeID int64) error
}
