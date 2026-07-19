package refresh

import (
	"AuthAPI/main/internal/models"
	"context"

	"github.com/google/uuid"
)

type RefreshTokenRepository interface {
	Create(ctx context.Context, t *models.RefreshToken) error
	FindValidByHash(ctx context.Context, hash string) (*models.RefreshToken, error)
	Revoke(ctx context.Context, tokenID uuid.UUID) error
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
}
