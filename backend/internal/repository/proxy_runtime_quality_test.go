package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func TestProxyRuntimeQualityAtomicallyDisablesBlockedProxy(t *testing.T) {
	repo, mock := newRuntimeRepoMock(t)
	mock.ExpectExec("(?s)WITH changed AS .*UPDATE proxy_runtimes.*UPDATE proxies").
		WithArgs(int64(7), "blocked", 30, "203.0.113.5", "US", "chatgpt_backend_blocked", "ChatGPT backend is blocked on this exit").
		WillReturnResult(sqlmock.NewResult(0, 1))
	err := repo.UpdateQualityByProxyID(context.Background(), 7, service.ProxyRuntimeQualitySnapshot{
		Status: "blocked", Score: 30, ExitIP: "203.0.113.5", CountryCode: "us",
		ErrorCode: "chatgpt_backend_blocked", ErrorText: "ChatGPT backend is blocked on this exit",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestProxyRuntimeQualityRejectsUnsafeValues(t *testing.T) {
	repo, mock := newRuntimeRepoMock(t)
	cases := []service.ProxyRuntimeQualitySnapshot{
		{Status: "active", Score: 100},
		{Status: "healthy", Score: 101},
		{Status: "blocked", Score: 0, ExitIP: "not-an-ip"},
		{Status: "degraded", Score: 50, ErrorCode: "SECRET OUTPUT"},
	}
	for _, snapshot := range cases {
		if err := repo.UpdateQualityByProxyID(context.Background(), 1, snapshot); !errors.Is(err, ErrProxyRuntimeInvalid) {
			t.Fatalf("unsafe snapshot accepted: %+v %v", snapshot, err)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
