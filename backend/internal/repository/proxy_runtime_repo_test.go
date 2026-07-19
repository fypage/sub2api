package repository

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func runtimeTestInput() ProxyRuntimeBatchInput {
	owner := int64(7)
	return ProxyRuntimeBatchInput{
		OwnerUserID: &owner,
		Source: &ProxyRuntimeSourceInput{
			Name: "subscription", SourceType: "singbox_subscription",
			SourceSecretEncrypted: "prx:v1:db-v1:source:ciphertext", EncryptionVersion: 1,
		},
		Runtimes: []ProxyRuntimeCreateInput{{
			Name: "node", Visibility: "private",
			NormalizedConfigEncrypted: "prx:v1:db-v1:config:ciphertext", EncryptionVersion: 1,
			NodeFingerprint: strings.Repeat("a", 64), ListenHost: "127.0.0.1", ListenPort: 21001,
			ListenUsername: "runtime-user-001", ListenPassword: strings.Repeat("p", 32),
		}},
	}
}

func newRuntimeRepoMock(t *testing.T) (*ProxyRuntimeRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewProxyRuntimeRepository(db), mock
}

func expectRuntimeSource(mock sqlmock.Sqlmock, id int64) {
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO proxy_runtime_sources")).
		WithArgs(int64(7), "subscription", "singbox_subscription", "prx:v1:db-v1:source:ciphertext", int16(1), 0, "", "").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id))
}

func expectPendingProxy(mock sqlmock.Sqlmock, id int64) {
	mock.ExpectQuery("INSERT INTO proxies[\\s\\S]+VALUES \\(\\$1, 'socks5h', \\$2, \\$3, \\$4, \\$5, 'disabled'").
		WithArgs("node", "127.0.0.1", 21001, "runtime-user-001", strings.Repeat("p", 32), "none", nil).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id))
}

func expectPendingRuntime(mock sqlmock.Sqlmock, id, proxyID, sourceID int64) {
	mock.ExpectQuery("INSERT INTO proxy_runtimes[\\s\\S]+'pending', TRUE").
		WithArgs(proxyID, sourceID, int64(7), "private", "prx:v1:db-v1:config:ciphertext", int16(1), strings.Repeat("a", 64), "", "127.0.0.1", 21001).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id))
}

func TestProxyRuntimeRepositoryCreateBatchIsAtomicAndPending(t *testing.T) {
	repo, mock := newRuntimeRepoMock(t)
	mock.ExpectBegin()
	expectRuntimeSource(mock, 11)
	expectPendingProxy(mock, 21)
	expectPendingRuntime(mock, 31, 21, 11)
	mock.ExpectCommit()

	result, err := repo.CreateBatch(context.Background(), runtimeTestInput())
	if err != nil {
		t.Fatal(err)
	}
	if result.SourceID == nil || *result.SourceID != 11 || len(result.Items) != 1 || result.Items[0].ProxyID != 21 || result.Items[0].RuntimeID != 31 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestProxyRuntimeRepositoryAllocatesPortInsideTransaction(t *testing.T) {
	repo, mock := newRuntimeRepoMock(t)
	input := runtimeTestInput()
	input.Runtimes[0].ListenPort = 0
	mock.ExpectBegin()
	expectRuntimeSource(mock, 11)
	mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT candidate[\\s\\S]+generate_series\\(\\$1::int, \\$2::int\\)").WithArgs(21000, 21999).
		WillReturnRows(sqlmock.NewRows([]string{"candidate"}).AddRow(21008))
	mock.ExpectQuery("INSERT INTO proxies[\\s\\S]+VALUES \\(\\$1, 'socks5h'").
		WithArgs("node", "127.0.0.1", 21008, "runtime-user-001", strings.Repeat("p", 32), "none", nil).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(21))
	mock.ExpectQuery("INSERT INTO proxy_runtimes[\\s\\S]+'pending', TRUE").
		WithArgs(int64(21), int64(11), int64(7), "private", "prx:v1:db-v1:config:ciphertext", int16(1), strings.Repeat("a", 64), "", "127.0.0.1", 21008).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(31))
	mock.ExpectCommit()
	if _, err := repo.CreateBatch(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestProxyRuntimeRepositoryCreateWithoutSource(t *testing.T) {
	repo, mock := newRuntimeRepoMock(t)
	input := runtimeTestInput()
	input.Source = nil
	mock.ExpectBegin()
	expectPendingProxy(mock, 21)
	mock.ExpectQuery("INSERT INTO proxy_runtimes[\\s\\S]+'pending', TRUE").
		WithArgs(int64(21), nil, int64(7), "private", "prx:v1:db-v1:config:ciphertext", int16(1), strings.Repeat("a", 64), "", "127.0.0.1", 21001).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(31))
	mock.ExpectCommit()
	result, err := repo.CreateBatch(context.Background(), input)
	if err != nil || result.SourceID != nil {
		t.Fatalf("unexpected source-less result: %+v %v", result, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestProxyRuntimeRepositoryRollsBackWholeBatch(t *testing.T) {
	repo, mock := newRuntimeRepoMock(t)
	mock.ExpectBegin()
	expectRuntimeSource(mock, 11)
	expectPendingProxy(mock, 21)
	mock.ExpectQuery("INSERT INTO proxy_runtimes").
		WillReturnError(errors.New("write failed"))
	mock.ExpectRollback()

	_, err := repo.CreateBatch(context.Background(), runtimeTestInput())
	if err == nil || errors.Is(err, ErrProxyRuntimeConflict) {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestProxyRuntimeRepositoryRollsBackWhenSecondRuntimeFails(t *testing.T) {
	repo, mock := newRuntimeRepoMock(t)
	input := runtimeTestInput()
	second := input.Runtimes[0]
	second.Name = "node-two"
	second.ListenPort = 21002
	second.NodeFingerprint = strings.Repeat("b", 64)
	input.Runtimes = append(input.Runtimes, second)
	mock.ExpectBegin()
	expectRuntimeSource(mock, 11)
	expectPendingProxy(mock, 21)
	expectPendingRuntime(mock, 31, 21, 11)
	mock.ExpectQuery("INSERT INTO proxies").WillReturnError(errors.New("second failed"))
	mock.ExpectRollback()
	if _, err := repo.CreateBatch(context.Background(), input); err == nil {
		t.Fatal("second item failure must fail whole batch")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestProxyRuntimeRepositoryValidatesBeforeTransaction(t *testing.T) {
	cases := []ProxyRuntimeBatchInput{
		{},
		func() ProxyRuntimeBatchInput {
			v := runtimeTestInput()
			v.Source.SourceSecretEncrypted = "plaintext"
			return v
		}(),
		func() ProxyRuntimeBatchInput {
			v := runtimeTestInput()
			v.Runtimes[0].NormalizedConfigEncrypted = "prx:v1:key:source:wrong"
			return v
		}(),
		func() ProxyRuntimeBatchInput { v := runtimeTestInput(); v.Runtimes[0].ListenHost = "0.0.0.0"; return v }(),
		func() ProxyRuntimeBatchInput { v := runtimeTestInput(); v.Runtimes[0].Visibility = "shared"; return v }(),
		func() ProxyRuntimeBatchInput { v := runtimeTestInput(); v.OwnerUserID = nil; return v }(),
		func() ProxyRuntimeBatchInput {
			v := runtimeTestInput()
			v.Runtimes = append(v.Runtimes, v.Runtimes[0])
			return v
		}(),
	}
	for i, input := range cases {
		repo, mock := newRuntimeRepoMock(t)
		_, err := repo.CreateBatch(context.Background(), input)
		if !errors.Is(err, ErrProxyRuntimeInvalid) {
			t.Fatalf("case %d: %v", i, err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("case %d touched database: %v", i, err)
		}
	}
}

func TestProxyRuntimeRepositoryRequiresDatabase(t *testing.T) {
	var nilRepo *ProxyRuntimeRepository
	if _, err := nilRepo.CreateBatch(context.Background(), runtimeTestInput()); err == nil {
		t.Fatal("nil repository must fail")
	}
	if _, err := NewProxyRuntimeRepository((*sql.DB)(nil)).CreateBatch(context.Background(), runtimeTestInput()); err == nil {
		t.Fatal("nil database must fail")
	}
}
