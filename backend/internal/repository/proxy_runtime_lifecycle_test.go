package repository

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestProxyRuntimeLifecycleLeaseTransitionsAtomically(t *testing.T) {
	repo, mock := newRuntimeRepoMock(t)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT pg_try_advisory_lock(hashtextextended('proxy_runtime:' || $1::text, 0))")).
		WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"locked"}).AddRow(true))
	lease, acquired, err := repo.TryAcquireLifecycleLease(context.Background(), 42)
	if err != nil || !acquired || lease == nil {
		t.Fatalf("lease acquisition failed: %v %v", acquired, err)
	}

	mock.ExpectQuery("SELECT r.id, r.proxy_id, r.owner_user_id, r.normalized_config_encrypted").WithArgs(int64(42)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "proxy_id", "owner_user_id", "normalized_config_encrypted", "encryption_version", "node_fingerprint", "source_node_key", "listen_host", "listen_port", "username", "password", "status", "auto_start", "restart_count"}).
			AddRow(42, 9, nil, "prx:v1:key:config:cipher", 1, strings.Repeat("a", 64), "", "127.0.0.1", 21001, "runtime-user-001", "runtime-password-0000000000000000", "pending", true, 0))
	snapshot, err := lease.Snapshot(context.Background())
	if err != nil || snapshot.ProxyID != 9 || snapshot.Status != "pending" {
		t.Fatalf("unexpected snapshot: %+v %v", snapshot, err)
	}

	mock.ExpectExec("(?s)WITH changed AS \\(.*UPDATE proxy_runtimes.*status = 'starting'.*UPDATE proxies").
		WithArgs(int64(42), `{"pending","stopped","error","degraded","blocked","healthy","starting"}`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := lease.MarkStarting(context.Background()); err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec("(?s)WITH changed AS \\(.*UPDATE proxy_runtimes.*status = 'healthy'.*UPDATE proxies").
		WithArgs(int64(42), `{"starting"}`, int64(1234), "/data/proxy-runtimes/42/config.json").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := lease.MarkHealthy(context.Background(), 1234, "/data/proxy-runtimes/42/config.json"); err != nil {
		t.Fatal(err)
	}

	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_unlock(hashtextextended('proxy_runtime:' || $1::text, 0))")).
		WithArgs(int64(42)).WillReturnResult(sqlmock.NewResult(0, 1))
	lease.Release()
	if err := lease.MarkStopped(context.Background(), false); !errors.Is(err, ErrProxyRuntimeLeaseReleased) {
		t.Fatalf("released lease remained usable: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestProxyRuntimeLifecycleLeaseContention(t *testing.T) {
	repo, mock := newRuntimeRepoMock(t)
	mock.ExpectQuery("pg_try_advisory_lock").WithArgs(int64(8)).
		WillReturnRows(sqlmock.NewRows([]string{"locked"}).AddRow(false))
	lease, acquired, err := repo.TryAcquireLifecycleLease(context.Background(), 8)
	if err != nil || acquired || lease != nil {
		t.Fatalf("unexpected contention result: %+v %v %v", lease, acquired, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestProxyRuntimeLifecycleRejectsInvalidTransitionsAndErrors(t *testing.T) {
	repo, mock := newRuntimeRepoMock(t)
	mock.ExpectQuery("pg_try_advisory_lock").WithArgs(int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"locked"}).AddRow(true))
	lease, acquired, err := repo.TryAcquireLifecycleLease(context.Background(), 7)
	if err != nil || !acquired {
		t.Fatal(err)
	}
	if err := lease.MarkHealthy(context.Background(), 0, "relative"); !errors.Is(err, ErrProxyRuntimeInvalid) {
		t.Fatalf("invalid process metadata accepted: %v", err)
	}
	if err := lease.MarkFailed(context.Background(), "SECRET OUTPUT", "safe", false); !errors.Is(err, ErrProxyRuntimeInvalid) {
		t.Fatalf("invalid error code accepted: %v", err)
	}
	mock.ExpectExec("status = 'starting'").WithArgs(int64(7), `{"pending","stopped","error","degraded","blocked","healthy","starting"}`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := lease.MarkStarting(context.Background()); !errors.Is(err, ErrProxyRuntimeStateConflict) {
		t.Fatalf("stale transition accepted: %v", err)
	}
	mock.ExpectExec("pg_advisory_unlock").WithArgs(int64(7)).WillReturnResult(sqlmock.NewResult(0, 1))
	lease.Release()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestProxyRuntimeLifecycleStopPersistsRecoveryIntent(t *testing.T) {
	repo, mock := newRuntimeRepoMock(t)
	mock.ExpectQuery("pg_try_advisory_lock").WithArgs(int64(9)).
		WillReturnRows(sqlmock.NewRows([]string{"locked"}).AddRow(true))
	lease, acquired, err := repo.TryAcquireLifecycleLease(context.Background(), 9)
	if err != nil || !acquired {
		t.Fatal(err)
	}
	mock.ExpectExec("(?s)status = 'stopped'.*auto_start = \\$3").
		WithArgs(int64(9), `{"pending","starting","healthy","degraded","blocked","error","stopped"}`, true).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := lease.MarkStopped(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec("pg_advisory_unlock").WithArgs(int64(9)).WillReturnResult(sqlmock.NewResult(0, 1))
	lease.Release()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestProxyRuntimeListAutoStartCandidatesIsBounded(t *testing.T) {
	repo, mock := newRuntimeRepoMock(t)
	mock.ExpectQuery("SELECT id FROM proxy_runtimes").WithArgs(512).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(2).AddRow(5))
	ids, err := repo.ListAutoStartRuntimeIDs(context.Background(), 9999)
	if err != nil || len(ids) != 2 || ids[0] != 2 || ids[1] != 5 {
		t.Fatalf("unexpected recovery candidates: %v %v", ids, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
