package auth

import (
	"AuthAPI/main/internal/models"
	"context"
)

type RefreshTokenRepository interface {
	Create(ctx context.Context, t *models.RefreshToken) error
	FindValidByHash(ctx context.Context, hash string) (*models.RefreshToken, error)
	Revoke(ctx context.Context, tokenID string) error
	RevokeAllForUser(ctx context.Context, userID string) error
}
