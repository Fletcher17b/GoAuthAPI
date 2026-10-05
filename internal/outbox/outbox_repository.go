package outbox

import (
	"AuthAPI/main/internal/auth/dbtx"
	"AuthAPI/main/internal/models"
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type outbox_repo struct {
	db dbtx.DBTX
}

func NewOutboxRepository(db *sql.DB) OutboxRepo {
	return &outbox_repo{db}
}

func (r *outbox_repo) CreateTx(ctx context.Context, exec dbtx.DBTX, outEvent *models.OutboxEvent) error {

	_, err := exec.ExecContext(
		ctx,
		`
		INSERT INTO outbox_events (
			id,
			aggregate_type,
			aggregate_id,
			event_type,
			payload,
			headers,
			status,
			retry_count,
			next_retry_at,
			created_at,
			published_at,
			last_error
		)
		VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10, $11, $12
		)
		`,
		outEvent.ID,
		outEvent.AggregateType,
		outEvent.AggregateID,
		outEvent.EventType,
		outEvent.Payload,
		outEvent.Headers,
		outEvent.Status,
		outEvent.RetryCount,
		outEvent.NextRetryAt,
		outEvent.CreatedAt,
		outEvent.PublishedAt,
		outEvent.LastError,
	)

	return err
}

func (r *outbox_repo) FetchPending(ctx context.Context, limit int) ([]*models.OutboxEvent, error) {
	rows, err := r.db.QueryContext(
		ctx,
		`
		SELECT
			id,
			aggregate_type,
			aggregate_id,
			event_type,
			payload,
			headers,
			status,
			retry_count,
			next_retry_at,
			created_at,
			published_at,
			last_error
		FROM outbox_events
		WHERE status IN ('Pending', 'Failed')
		  AND next_retry_at <= now()
		ORDER BY created_at ASC
		LIMIT $1
		FOR UPDATE SKIP LOCKED
		`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var events []*models.OutboxEvent
	for rows.Next() {
		var e models.OutboxEvent
		var headers []byte
		if err := rows.Scan(
			&e.ID,
			&e.AggregateType,
			&e.AggregateID,
			&e.EventType,
			&e.Payload,
			&headers,
			&e.Status,
			&e.RetryCount,
			&e.NextRetryAt,
			&e.CreatedAt,
			&e.PublishedAt,
			&e.LastError,
		); err != nil {
			return nil, err
		}
		if headers != nil {
			e.Headers = json.RawMessage(headers)
		}
		events = append(events, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return events, nil
}

// ClaimBatch atomically selects and locks up to limit eligible rows in a
// single statement (a CTE-scoped SELECT ... FOR UPDATE SKIP LOCKED feeding
// an UPDATE ... RETURNING). Because it's one statement, Postgres holds the
// row locks only for the duration of that statement - there is no
// separate Go-level transaction left open afterward, so the caller is
// free to do network I/O (the actual publish) with zero locks held.
//
// A row is eligible if it's:
//   - pending (never attempted, or a prior claim on it expired and it was
//     reset - see note below), or
//   - processing but its locked_until has passed (a previous worker
//     claimed it and crashed/hung before marking it published/failed -
//     this is the crash-recovery path), or
//   - failed and its backoff window (next_retry_at) has elapsed.
func (r *outbox_repo) ClaimBatch(
	ctx context.Context,
	limit int,
	workerID string,
	lockDuration time.Duration,
) ([]*models.OutboxEvent, error) {
	rows, err := r.db.QueryContext(
		ctx,
		`
		WITH claimed AS (
			SELECT id
			FROM outbox_events
			WHERE
				(status = 'pending')
				OR (status = 'processing' AND locked_until < NOW())
				OR (status = 'failed' AND next_retry_at <= NOW())
			ORDER BY created_at ASC
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE outbox_events o
		SET status = 'processing',
		    locked_at = NOW(),
		    locked_until = NOW() + $2 * INTERVAL '1 second',
		    locked_by = $3
		FROM claimed
		WHERE o.id = claimed.id
		RETURNING
			o.id,
			o.aggregate_type,
			o.aggregate_id,
			o.event_type,
			o.payload,
			o.headers,
			o.status,
			o.retry_count,
			o.next_retry_at,
			o.created_at,
			o.published_at,
			o.last_error,
			o.locked_at,
			o.locked_until,
			o.locked_by
		`,
		limit,
		lockDuration.Seconds(),
		workerID,
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var events []*models.OutboxEvent
	for rows.Next() {
		var e models.OutboxEvent
		var headers []byte
		if err := rows.Scan(
			&e.ID,
			&e.AggregateType,
			&e.AggregateID,
			&e.EventType,
			&e.Payload,
			&headers,
			&e.Status,
			&e.RetryCount,
			&e.NextRetryAt,
			&e.CreatedAt,
			&e.PublishedAt,
			&e.LastError,
			&e.LockedAt,
			&e.LockedUntil,
			&e.LockedBy,
		); err != nil {
			return nil, err
		}
		if headers != nil {
			e.Headers = json.RawMessage(headers)
		}
		events = append(events, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return events, nil
}

func (r *outbox_repo) MarkPublished(ctx context.Context, id uuid.UUID, publishedAt time.Time) error {
	_, err := r.db.ExecContext(
		ctx,
		`
		UPDATE outbox_events
		SET status = $1,
		    published_at = $2,
		    last_error = NULL
		WHERE id = $3
		`,
		models.StatusPublished,
		publishedAt,
		id,
	)
	return err
}

func (r *outbox_repo) MarkFailed(ctx context.Context, id uuid.UUID, nextRetryAt time.Time, lastErr string) error {
	_, err := r.db.ExecContext(
		ctx,
		`
		UPDATE outbox_events
		SET status = $1,
		    retry_count = retry_count + 1,
		    next_retry_at = $2,
		    last_error = $3
		WHERE id = $4
		`,
		models.StatusFailed,
		nextRetryAt,
		lastErr,
		id,
	)
	return err
}

func (r *outbox_repo) Create(ctx context.Context, outEvent *models.OutboxEvent) error {

	_, err := r.db.ExecContext(
		ctx,
		`
		INSERT INTO outbox_events (
			id,
			aggregate_type,
			aggregate_id,
			event_type,
			payload,
			headers,
			status,
			retry_count,
			next_retry_at,
			created_at,
			published_at,
			last_error
		)
		VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10, $11, $12
		)
		`,
		outEvent.ID,
		outEvent.AggregateType,
		outEvent.AggregateID,
		outEvent.EventType,
		outEvent.Payload,
		outEvent.Headers,
		outEvent.Status,
		outEvent.RetryCount,
		outEvent.NextRetryAt,
		outEvent.CreatedAt,
		outEvent.PublishedAt,
		outEvent.LastError,
	)

	return err
}
