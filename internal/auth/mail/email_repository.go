package mail

import (
	"context"
	"time"

	"AuthAPI/main/internal/models"
)

type EmailVerificationRepository interface {
	Create(ctx context.Context, t *models.EmailVerificationToken) error
	FindValidByHash(ctx context.Context, hash string) (*models.EmailVerificationToken, error)
	MarkUsed(ctx context.Context, tokenID string, usedAt time.Time) error
	DeleteAllForUser(ctx context.Context, userID string) error
}
