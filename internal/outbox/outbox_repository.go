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

// FetchPending selects events that are due for (re)publishing, oldest first.
// FOR UPDATE SKIP LOCKED lets multiple worker instances poll concurrently
// without picking up the same rows.
//
// Note: r.db is a dbtx.DBTX (not a *sql.Tx), so this runs as its own
// implicit transaction and the row locks are released as soon as the
// SELECT completes. That's fine for reducing duplicate publishes under
// light concurrency, but if you need a hard guarantee that a row can't be
// picked up again until it's marked, move the fetch+mark into a single
// caller-managed transaction using CreateTx-style plumbing.
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
	defer rows.Close()

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
