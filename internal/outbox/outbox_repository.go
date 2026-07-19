package outbox

import (
	"AuthAPI/main/internal/models"
	"context"
	"database/sql"
)

type outbox_repo struct {
	db *sql.DB
}

func NewOutboxRepository(db *sql.DB) OutboxRepo {
	return &outbox_repo{db}
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
