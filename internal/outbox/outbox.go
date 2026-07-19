package outbox

import (
	"AuthAPI/main/internal/models"
	"context"
	"database/sql"
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
	Create(ctx context.Context, u *models.OutboxEvent) error
}
