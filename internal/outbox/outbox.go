package outbox

import (
	"AuthAPI/main/internal/auth/dbtx"
	"AuthAPI/main/internal/models"
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

func NewOutboxRepoAuxiliary(driver string, db *sql.DB) OutboxRepo {
	switch driver {
	case "sqlite":
		panic("Sqlite no support for Outbox Events")
	case "postgres":
		return NewOutboxRepository(db)
	default:
		panic("unsupported database driver")
	}
}

type OutboxRepo interface {
	CreateTx(ctx context.Context, exec dbtx.DBTX, u *models.OutboxEvent) error
	Create(ctx context.Context, u *models.OutboxEvent) error
	FetchPending(ctx context.Context, limit int) ([]*models.OutboxEvent, error)
	MarkPublished(ctx context.Context, id uuid.UUID, publishedAt time.Time) error
	MarkFailed(ctx context.Context, id uuid.UUID, nextRetryAt time.Time, lastErr string) error
}
