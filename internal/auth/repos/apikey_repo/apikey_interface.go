package apikeyrepo

import (
	"AuthAPI/main/internal/auth/dbtx"
	"AuthAPI/main/internal/models"
	"context"

	"github.com/google/uuid"
)

type ApiKeyRepository interface {
	CreateTx(ctx context.Context, exec dbtx.DBTX, t *models.Apikey_model) error
	UpdateTx(ctx context.Context, exec dbtx.DBTX, t *models.Apikey_model) error
	FindbyHash(ctx context.Context, exec dbtx.DBTX, hash string, consumerID uuid.UUID) (*models.Apikey_model, error)
	//FindbyOwner(ctx context.Context, exec dbtx.DBTX, consumerID uuid.UUID) (*models.Apikey_model, error)
	RegisterUse(ctx context.Context, exec dbtx.DBTX, apikey_id uuid.UUID) error
	Revoke(ctx context.Context, exec dbtx.DBTX, apikey_id uuid.UUID, consumerID uuid.UUID) error
}
