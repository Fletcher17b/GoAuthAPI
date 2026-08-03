package mail

import (
	"context"
	"time"

	"AuthAPI/main/internal/auth/dbtx"
	"AuthAPI/main/internal/models"

	"github.com/google/uuid"
)

type EmailVerificationRepository interface {
	Create(ctx context.Context, t *models.EmailVerificationToken) error
	CreateTx(ctx context.Context, exec dbtx.DBTX, t *models.EmailVerificationToken) error
	FindValidByHash(ctx context.Context, hash string) (*models.EmailVerificationToken, error)
	MarkUsed(ctx context.Context, tokenID uuid.UUID, usedAt time.Time) error
	DeleteAllForUser(ctx context.Context, userID uuid.UUID) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
}
