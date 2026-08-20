package outbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"AuthAPI/main/internal/models"
	"AuthAPI/main/internal/tests"

	"github.com/google/uuid"
)

var (
	pgTestDB            *sql.DB
	pgDockerUnavailable string
)

func TestMain(m *testing.M) {
	var teardown func()
	pgTestDB, pgDockerUnavailable, teardown = tests.SetupTestDB()
	defer teardown()
	os.Exit(m.Run())
}

func requirePostgres(t *testing.T) *sql.DB {
	return tests.RequirePostgres(t, pgTestDB, pgDockerUnavailable)
}

func newOutboxEvent() *models.OutboxEvent {
	now := time.Now().UTC().Truncate(time.Microsecond)

	return &models.OutboxEvent{
		ID:            uuid.New(),
		AggregateType: "user",
		AggregateID:   uuid.New(),
		EventType:     models.UserCreated,
		Payload:       json.RawMessage(`{"email":"user@example.com"}`),
		Headers:       nil,
		Status:        models.StatusPending,
		RetryCount:    0,
		NextRetryAt:   now,
		CreatedAt:     now,
		PublishedAt:   nil,
		LastError:     nil,
	}
}

func dbNow(t *testing.T, ctx context.Context, tx *sql.Tx) time.Time {
	t.Helper()
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT NOW()").Scan(&now); err != nil {
		t.Fatalf("failed to query db now(): %v", err)
	}
	return now
}

// newDueOutboxEvent builds an event whose next_retry_at/created_at are
// already due according to Postgres's own clock (see dbNow), for tests that
// rely on FetchPending's "next_retry_at <= now()" filter actually matching.
func newDueOutboxEvent(t *testing.T, ctx context.Context, tx *sql.Tx) *models.OutboxEvent {
	t.Helper()
	e := newOutboxEvent()
	now := dbNow(t, ctx, tx)
	e.CreatedAt = now
	e.NextRetryAt = now
	return e
}

// assertJSONEqual compares two JSON documents semantically rather than byte-for-byte.
func assertJSONEqual(t *testing.T, got, want []byte, msgPrefix string) {
	t.Helper()

	var gotVal, wantVal any
	if err := json.Unmarshal(got, &gotVal); err != nil {
		t.Fatalf("%s: failed to unmarshal got JSON %s: %v", msgPrefix, got, err)
	}
	if err := json.Unmarshal(want, &wantVal); err != nil {
		t.Fatalf("%s: failed to unmarshal want JSON %s: %v", msgPrefix, want, err)
	}

	gotNorm, err := json.Marshal(gotVal)
	if err != nil {
		t.Fatalf("%s: failed to re-marshal got JSON: %v", msgPrefix, err)
	}
	wantNorm, err := json.Marshal(wantVal)
	if err != nil {
		t.Fatalf("%s: failed to re-marshal want JSON: %v", msgPrefix, err)
	}

	if string(gotNorm) != string(wantNorm) {
		t.Errorf("%s: JSON mismatch\ngot:  %s\nwant: %s", msgPrefix, got, want)
	}
}

func withOutboxTx(t *testing.T, fn func(ctx context.Context, tx *sql.Tx, repo *outbox_repo)) {
	t.Helper()
	db := requirePostgres(t)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("failed to begin tx: %v", err)
	}
	t.Cleanup(func() {
		_ = tx.Rollback()
	})

	repo := &outbox_repo{db: tx}
	fn(ctx, tx, repo)
}

// ---------- NewOutboxRepo ----------
func TestNewOutboxRepo(t *testing.T) {
	t.Run("sqlite driver panics (unsupported)", func(t *testing.T) {
		db := requirePostgres(t) // any *sql.DB works, sqlite branch panics before using it

		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for sqlite driver, got none")
			}
		}()

		NewOutboxRepo("sqlite", db)
	})

	t.Run("postgres driver returns a working repo", func(t *testing.T) {
		db := requirePostgres(t)

		repo := NewOutboxRepo("postgres", db)
		if repo == nil {
			t.Fatal("expected non-nil repo for postgres driver")
		}
	})

	t.Run("unknown driver panics", func(t *testing.T) {
		db := requirePostgres(t)

		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for unknown driver, got none")
			}
		}()

		NewOutboxRepo("mongodb", db)
	})
}

// ---------- Create / CreateTx ----------
func TestOutboxRepo_Create(t *testing.T) {
	withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
		event := newOutboxEvent()

		if err := repo.Create(ctx, event); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		var status string
		var payload []byte
		err := tx.QueryRowContext(ctx, `
			SELECT status, payload FROM outbox_events WHERE id = $1
		`, event.ID).Scan(&status, &payload)
		if err != nil {
			t.Fatalf("failed to query created event: %v", err)
		}
		if status != string(models.StatusPending) {
			t.Errorf("status = %q, want %q", status, models.StatusPending)
		}
		assertJSONEqual(t, payload, event.Payload, "payload")
	})
}

func TestOutboxRepo_Create_NilHeadersStoredAsNull(t *testing.T) {
	withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
		event := newOutboxEvent()
		event.Headers = nil

		if err := repo.Create(ctx, event); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		var headers sql.NullString
		err := tx.QueryRowContext(ctx, `
			SELECT headers FROM outbox_events WHERE id = $1
		`, event.ID).Scan(&headers)
		if err != nil {
			t.Fatalf("failed to query event: %v", err)
		}
		if headers.Valid {
			t.Errorf("headers = %q, want NULL", headers.String)
		}
	})
}

func TestOutboxRepo_Create_WithHeaders(t *testing.T) {
	withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
		event := newOutboxEvent()
		event.Headers = json.RawMessage(`{"trace_id":"abc-123"}`)

		if err := repo.Create(ctx, event); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		var headers []byte
		err := tx.QueryRowContext(ctx, `
			SELECT headers FROM outbox_events WHERE id = $1
		`, event.ID).Scan(&headers)
		if err != nil {
			t.Fatalf("failed to query event: %v", err)
		}
		assertJSONEqual(t, headers, event.Headers, "headers")
	})
}

func TestOutboxRepo_Create_WithHeaders_SemanticComparison(t *testing.T) {
	withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
		event := newOutboxEvent()
		event.Headers = json.RawMessage(`{"trace_id":  "abc-123",   "retry":true}`)

		if err := repo.Create(ctx, event); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		var headers []byte
		err := tx.QueryRowContext(ctx, `
			SELECT headers FROM outbox_events WHERE id = $1
		`, event.ID).Scan(&headers)
		if err != nil {
			t.Fatalf("failed to query event: %v", err)
		}
		assertJSONEqual(t, headers, event.Headers, "headers")
	})
}

func TestOutboxRepo_Create_DuplicateIDFails(t *testing.T) {
	withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
		event := newOutboxEvent()
		if err := repo.Create(ctx, event); err != nil {
			t.Fatalf("unexpected error creating first event: %v", err)
		}

		dup := newOutboxEvent()
		dup.ID = event.ID // same primary key

		if err := repo.Create(ctx, dup); err == nil {
			t.Fatal("expected primary key violation for duplicate id, got nil")
		}
	})
}

func TestOutboxRepo_CreateTx(t *testing.T) {
	withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
		event := newOutboxEvent()

		if err := repo.CreateTx(ctx, tx, event); err != nil {
			t.Fatalf("CreateTx() error = %v", err)
		}

		var count int
		err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM outbox_events WHERE id = $1
		`, event.ID).Scan(&count)
		if err != nil {
			t.Fatalf("failed to query event: %v", err)
		}
		if count != 1 {
			t.Fatalf("event count = %d, want 1", count)
		}
	})
}

func TestOutboxRepo_CreateTx_RollbackDiscardsInsert(t *testing.T) {
	withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
		if _, err := tx.ExecContext(ctx, "SAVEPOINT create_tx_test"); err != nil {
			t.Fatalf("failed to create savepoint: %v", err)
		}

		event := newOutboxEvent()
		if err := repo.CreateTx(ctx, tx, event); err != nil {
			t.Fatalf("CreateTx() error = %v", err)
		}

		if _, err := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT create_tx_test"); err != nil {
			t.Fatalf("failed to roll back to savepoint: %v", err)
		}

		var count int
		err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM outbox_events WHERE id = $1
		`, event.ID).Scan(&count)
		if err != nil {
			t.Fatalf("failed to query event: %v", err)
		}
		if count != 0 {
			t.Fatalf("event count = %d after rollback, want 0", count)
		}
	})
}

func TestOutboxRepo_Create_ContextCanceled(t *testing.T) {
	withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		err := repo.Create(cctx, newOutboxEvent())
		if err == nil {
			t.Fatal("Create() error = nil, want context cancellation error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Create() error = %v, want context.Canceled", err)
		}
	})
}

// ---------- FetchPending ----------
func TestOutboxRepo_FetchPending(t *testing.T) {
	t.Run("returns pending events due now, oldest first", func(t *testing.T) {
		withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
			now := dbNow(t, ctx, tx)

			older := newDueOutboxEvent(t, ctx, tx)
			older.CreatedAt = now.Add(-time.Hour)

			newer := newDueOutboxEvent(t, ctx, tx)
			newer.CreatedAt = now

			if err := repo.Create(ctx, older); err != nil {
				t.Fatalf("Create(older) error = %v", err)
			}
			if err := repo.Create(ctx, newer); err != nil {
				t.Fatalf("Create(newer) error = %v", err)
			}

			got, err := repo.FetchPending(ctx, 10)
			if err != nil {
				t.Fatalf("FetchPending() error = %v", err)
			}
			if len(got) != 2 {
				t.Fatalf("len(got) = %d, want 2", len(got))
			}
			if got[0].ID != older.ID {
				t.Errorf("got[0].ID = %v, want older event %v (expected oldest-first order)", got[0].ID, older.ID)
			}
			if got[1].ID != newer.ID {
				t.Errorf("got[1].ID = %v, want newer event %v", got[1].ID, newer.ID)
			}
		})
	})

	t.Run("includes Failed status, excludes Published and Publishing", func(t *testing.T) {
		withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
			failed := newDueOutboxEvent(t, ctx, tx)
			failed.Status = models.StatusFailed

			published := newDueOutboxEvent(t, ctx, tx)
			published.Status = models.StatusPublished

			publishing := newDueOutboxEvent(t, ctx, tx)
			publishing.Status = models.StatusPublishing

			for _, e := range []*models.OutboxEvent{failed, published, publishing} {
				if err := repo.Create(ctx, e); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
			}

			got, err := repo.FetchPending(ctx, 10)
			if err != nil {
				t.Fatalf("FetchPending() error = %v", err)
			}

			ids := map[uuid.UUID]bool{}
			for _, e := range got {
				ids[e.ID] = true
			}
			if !ids[failed.ID] {
				t.Error("expected Failed event to be included")
			}
			if ids[published.ID] {
				t.Error("expected Published event to be excluded")
			}
			if ids[publishing.ID] {
				t.Error("expected Publishing event to be excluded")
			}
		})
	})

	t.Run("excludes events whose next_retry_at is in the future", func(t *testing.T) {
		withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
			now := dbNow(t, ctx, tx)

			notYetDue := newOutboxEvent()
			notYetDue.NextRetryAt = now.Add(time.Hour)

			due := newOutboxEvent()
			due.NextRetryAt = now.Add(-time.Minute)

			if err := repo.Create(ctx, notYetDue); err != nil {
				t.Fatalf("Create(notYetDue) error = %v", err)
			}
			if err := repo.Create(ctx, due); err != nil {
				t.Fatalf("Create(due) error = %v", err)
			}

			got, err := repo.FetchPending(ctx, 10)
			if err != nil {
				t.Fatalf("FetchPending() error = %v", err)
			}

			ids := map[uuid.UUID]bool{}
			for _, e := range got {
				ids[e.ID] = true
			}
			if !ids[due.ID] {
				t.Error("expected due event to be included")
			}
			if ids[notYetDue.ID] {
				t.Error("expected not-yet-due event to be excluded")
			}
		})
	})

	t.Run("respects limit", func(t *testing.T) {
		withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
			for i := 0; i < 5; i++ {
				if err := repo.Create(ctx, newDueOutboxEvent(t, ctx, tx)); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
			}

			got, err := repo.FetchPending(ctx, 3)
			if err != nil {
				t.Fatalf("FetchPending() error = %v", err)
			}
			if len(got) != 3 {
				t.Fatalf("len(got) = %d, want 3", len(got))
			}
		})
	})

	t.Run("empty table returns empty slice, no error", func(t *testing.T) {
		withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
			got, err := repo.FetchPending(ctx, 10)
			if err != nil {
				t.Fatalf("FetchPending() error = %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("len(got) = %d, want 0", len(got))
			}
		})
	})

	t.Run("nil headers scanned as nil json.RawMessage", func(t *testing.T) {
		withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
			event := newDueOutboxEvent(t, ctx, tx)
			event.Headers = nil

			if err := repo.Create(ctx, event); err != nil {
				t.Fatalf("Create() error = %v", err)
			}

			got, err := repo.FetchPending(ctx, 10)
			if err != nil {
				t.Fatalf("FetchPending() error = %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("len(got) = %d, want 1", len(got))
			}
			if got[0].Headers != nil {
				t.Errorf("Headers = %s, want nil", got[0].Headers)
			}
		})
	})

	t.Run("context canceled", func(t *testing.T) {
		withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
			cctx, cancel := context.WithCancel(ctx)
			cancel()

			_, err := repo.FetchPending(cctx, 10)
			if err == nil {
				t.Fatal("FetchPending() error = nil, want context cancellation error")
			}
			if !errors.Is(err, context.Canceled) {
				t.Errorf("FetchPending() error = %v, want context.Canceled", err)
			}
		})
	})
}

func TestOutboxRepo_FetchPending_SkipLockedConcurrency(t *testing.T) {
	db := requirePostgres(t)
	ctx := context.Background()

	// Seed data in its own committed setup transaction so both fetcher transactions can see it
	setupTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("failed to begin setup tx: %v", err)
	}
	setupRepo := &outbox_repo{db: setupTx}

	const totalEvents = 10
	eventIDs := make(map[uuid.UUID]bool, totalEvents)
	for i := 0; i < totalEvents; i++ {
		e := newDueOutboxEvent(t, ctx, setupTx)
		if err := setupRepo.Create(ctx, e); err != nil {
			_ = setupTx.Rollback()
			t.Fatalf("Create() error = %v", err)
		}
		eventIDs[e.ID] = true
	}
	if err := setupTx.Commit(); err != nil {
		t.Fatalf("failed to commit setup tx: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `
			DELETE FROM outbox_events WHERE id::text = ANY($1)
		`, uuidsToStrings(eventIDs))
	})

	tx1, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("failed to begin tx1: %v", err)
	}
	defer tx1.Rollback() //nolint:errcheck

	tx2, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("failed to begin tx2: %v", err)
	}
	defer tx2.Rollback() //nolint:errcheck

	repo1 := &outbox_repo{db: tx1}
	repo2 := &outbox_repo{db: tx2}

	var (
		wg         sync.WaitGroup
		got1, got2 []*models.OutboxEvent
		err1, err2 error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		got1, err1 = repo1.FetchPending(ctx, 5)
	}()
	go func() {
		defer wg.Done()
		got2, err2 = repo2.FetchPending(ctx, 5)
	}()
	wg.Wait()

	if err1 != nil {
		t.Fatalf("repo1.FetchPending() error = %v", err1)
	}
	if err2 != nil {
		t.Fatalf("repo2.FetchPending() error = %v", err2)
	}

	seen := map[uuid.UUID]bool{}
	for _, e := range got1 {
		seen[e.ID] = true
	}
	for _, e := range got2 {
		if seen[e.ID] {
			t.Errorf("event %v was returned by both concurrent FetchPending calls; "+
				"FOR UPDATE SKIP LOCKED should prevent this", e.ID)
		}
	}

	if len(got1)+len(got2) == 0 {
		t.Fatal("expected at least some events to be fetched across both concurrent calls")
	}
}

func uuidsToStrings(ids map[uuid.UUID]bool) []string {
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id.String())
	}
	return out
}

// ---------- MarkPublished ----------

func TestOutboxRepo_MarkPublished(t *testing.T) {
	withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
		event := newOutboxEvent()
		event.Status = models.StatusFailed
		lastErr := "previous failure"
		event.LastError = &lastErr

		if err := repo.Create(ctx, event); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		publishedAt := time.Now().UTC().Truncate(time.Microsecond)
		if err := repo.MarkPublished(ctx, event.ID, publishedAt); err != nil {
			t.Fatalf("MarkPublished() error = %v", err)
		}

		var status string
		var gotPublishedAt time.Time
		var lastError sql.NullString
		err := tx.QueryRowContext(ctx, `
			SELECT status, published_at, last_error FROM outbox_events WHERE id = $1
		`, event.ID).Scan(&status, &gotPublishedAt, &lastError)
		if err != nil {
			t.Fatalf("failed to query event: %v", err)
		}

		if status != string(models.StatusPublished) {
			t.Errorf("status = %q, want %q", status, models.StatusPublished)
		}
		if !gotPublishedAt.Equal(publishedAt) {
			t.Errorf("published_at = %v, want %v", gotPublishedAt, publishedAt)
		}
		if lastError.Valid {
			t.Errorf("last_error = %q, want NULL (should be cleared on publish)", lastError.String)
		}
	})
}

func TestOutboxRepo_MarkPublished_NonExistentIDSucceedsSilently(t *testing.T) {
	/*
		nts: documents current behavior. UPDATE ... WHERE id = ? matching zero
		rows is not an error in database/sql. If callers need to know whether
		the event actually existed, MarkPublished should check RowsAffected().
	*/
	withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
		err := repo.MarkPublished(ctx, uuid.New(), time.Now().UTC())
		if err != nil {
			t.Fatalf("expected no error for nonexistent id (current behavior), got: %v", err)
		}
	})
}

func TestOutboxRepo_MarkPublished_ContextCanceled(t *testing.T) {
	withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		err := repo.MarkPublished(cctx, uuid.New(), time.Now().UTC())
		if err == nil {
			t.Fatal("MarkPublished() error = nil, want context cancellation error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("MarkPublished() error = %v, want context.Canceled", err)
		}
	})
}

// ---------- MarkFailed ----------

func TestOutboxRepo_MarkFailed(t *testing.T) {
	withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
		event := newOutboxEvent()
		event.RetryCount = 2

		if err := repo.Create(ctx, event); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		nextRetryAt := time.Now().UTC().Add(5 * time.Minute).Truncate(time.Microsecond)
		if err := repo.MarkFailed(ctx, event.ID, nextRetryAt, "connection refused"); err != nil {
			t.Fatalf("MarkFailed() error = %v", err)
		}

		var status string
		var retryCount int
		var gotNextRetryAt time.Time
		var lastError sql.NullString
		err := tx.QueryRowContext(ctx, `
			SELECT status, retry_count, next_retry_at, last_error FROM outbox_events WHERE id = $1
		`, event.ID).Scan(&status, &retryCount, &gotNextRetryAt, &lastError)
		if err != nil {
			t.Fatalf("failed to query event: %v", err)
		}

		if status != string(models.StatusFailed) {
			t.Errorf("status = %q, want %q", status, models.StatusFailed)
		}
		if retryCount != 3 {
			t.Errorf("retry_count = %d, want 3 (incremented from 2)", retryCount)
		}
		if !gotNextRetryAt.Equal(nextRetryAt) {
			t.Errorf("next_retry_at = %v, want %v", gotNextRetryAt, nextRetryAt)
		}
		if !lastError.Valid || lastError.String != "connection refused" {
			t.Errorf("last_error = %v, want %q", lastError, "connection refused")
		}
	})
}

func TestOutboxRepo_MarkFailed_IncrementsRetryCountAcrossMultipleFailures(t *testing.T) {
	withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
		event := newOutboxEvent()
		if err := repo.Create(ctx, event); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		for i := 1; i <= 3; i++ {
			if err := repo.MarkFailed(ctx, event.ID, time.Now().UTC(), "retry attempt"); err != nil {
				t.Fatalf("MarkFailed() call %d error = %v", i, err)
			}
		}

		var retryCount int
		err := tx.QueryRowContext(ctx, `
			SELECT retry_count FROM outbox_events WHERE id = $1
		`, event.ID).Scan(&retryCount)
		if err != nil {
			t.Fatalf("failed to query event: %v", err)
		}
		if retryCount != 3 {
			t.Errorf("retry_count = %d, want 3", retryCount)
		}
	})
}

func TestOutboxRepo_MarkFailed_NonExistentIDSucceedsSilently(t *testing.T) {
	withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
		err := repo.MarkFailed(ctx, uuid.New(), time.Now().UTC(), "some error")
		if err != nil {
			t.Fatalf("expected no error for nonexistent id (current behavior), got: %v", err)
		}
	})
}

func TestOutboxRepo_MarkFailed_ContextCanceled(t *testing.T) {
	withOutboxTx(t, func(ctx context.Context, tx *sql.Tx, repo *outbox_repo) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		err := repo.MarkFailed(cctx, uuid.New(), time.Now().UTC(), "err")
		if err == nil {
			t.Fatal("MarkFailed() error = nil, want context cancellation error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("MarkFailed() error = %v, want context.Canceled", err)
		}
	})
}
