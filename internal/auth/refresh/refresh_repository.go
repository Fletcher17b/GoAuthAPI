package refresh

import (
	"AuthAPI/main/internal/auth/dbtx"
	"AuthAPI/main/internal/models"
	"context"

	"github.com/google/uuid"
)

type RefreshTokenRepository interface {
	Create(ctx context.Context, t *models.RefreshToken) error
	CreateTx(ctx context.Context, exec dbtx.DBTX, t *models.RefreshToken) error
	FindbyHash(ctx context.Context, exec dbtx.DBTX, hash string) (*models.RefreshToken, error)
	FindValidByHash(ctx context.Context, hash string) (*models.RefreshToken, error)
	Revoke(ctx context.Context, exec dbtx.DBTX, tokenID uuid.UUID) error
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
	RevokeAllForFamily(ctx context.Context, exec dbtx.DBTX, familyID uuid.UUID) error
}

func nullableUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
