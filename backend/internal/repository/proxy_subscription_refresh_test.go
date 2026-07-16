package repository

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSubscriptionRefreshLeaseContention(t *testing.T) {
	repo, mock := newRuntimeRepoMock(t)
	mock.ExpectQuery("pg_try_advisory_lock").WithArgs(int64(4)).
		WillReturnRows(sqlmock.NewRows([]string{"locked"}).AddRow(false))
	lease, acquired, err := repo.TryAcquireSubscriptionRefreshLease(context.Background(), 4)
	if err != nil || acquired || lease != nil {
		t.Fatalf("unexpected lease contention result: %+v %v %v", lease, acquired, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestListDueSubscriptionSourcesIsBounded(t *testing.T) {
	repo, mock := newRuntimeRepoMock(t)
	mock.ExpectQuery("SELECT id, source_secret_encrypted").WithArgs(100).
		WillReturnRows(sqlmock.NewRows([]string{"id", "source_secret_encrypted", "etag", "last_modified"}).
			AddRow(1, "prx:v1:key:source:cipher", `"v1"`, "Mon"))
	items, err := repo.ListDueSubscriptionSources(context.Background(), 999)
	if err != nil || len(items) != 1 || items[0].SourceID != 1 {
		t.Fatalf("unexpected due sources: %+v %v", items, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecordSubscriptionSyncUsesRedactedMetadata(t *testing.T) {
	repo, mock := newRuntimeRepoMock(t)
	mock.ExpectExec("UPDATE proxy_runtime_sources").
		WithArgs(int64(3), "partial", `"v2"`, "Tue", "", "").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repo.RecordSubscriptionSync(context.Background(), 3, "partial", `"v2"`, "Tue", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecordSubscriptionDeferredRetriesWithoutAdvancingValidators(t *testing.T) {
	repo, mock := newRuntimeRepoMock(t)
	mock.ExpectExec("UPDATE proxy_runtime_sources").WithArgs(int64(5)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repo.RecordSubscriptionDeferred(context.Background(), 5); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMarkRemovedSubscriptionRuntimeDisablesProxy(t *testing.T) {
	repo, mock := newRuntimeRepoMock(t)
	mock.ExpectExec("(?s)WITH changed AS .*subscription_node_removed.*UPDATE proxies").
		WithArgs(int64(8)).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repo.MarkSubscriptionRuntimeRemoved(context.Background(), 8); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
