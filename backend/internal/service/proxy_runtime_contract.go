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

type ProxyRuntimeStatus struct {
	ID                int64  `json:"id"`
	ProxyID           int64  `json:"proxy_id"`
	Status            string `json:"status"`
	AutoStart         bool   `json:"auto_start"`
	RestartCount      int    `json:"restart_count"`
	LastErrorCode     string `json:"last_error_code,omitempty"`
	LastErrorRedacted string `json:"last_error_redacted,omitempty"`
	ListenHost        string `json:"listen_host"`
	ListenPort        int    `json:"listen_port"`
}

type ProxyRuntimeCreated struct {
	ProxyID   int64
	RuntimeID int64
	Status    string
}

type ProxyRuntimeQualitySnapshot struct {
	Status      string
	Score       int
	ExitIP      string
	CountryCode string
	ErrorCode   string
	ErrorText   string
}

type ProxyRuntimeController interface {
	Status(ctx context.Context, proxyID int64) (*ProxyRuntimeStatus, error)
	Stop(ctx context.Context, runtimeID int64) error
	RecordQuality(ctx context.Context, proxyID int64, snapshot ProxyRuntimeQualitySnapshot) error
}

type ProxyRuntimeAdminService interface {
	Preview(ctx context.Context, input string) ([]ProxyRuntimePreview, error)
	Status(ctx context.Context, proxyID int64) (*ProxyRuntimeStatus, error)
	Create(ctx context.Context, request ProxyRuntimeCreateRequest) (*ProxyRuntimeCreated, error)
	Start(ctx context.Context, runtimeID int64) error
	Stop(ctx context.Context, runtimeID int64) error
}
