package users

import (
	"AuthAPI/main/internal/auth/dbtx"
	"AuthAPI/main/internal/models"
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	Create(ctx context.Context, u *models.User) error
	CreateTx(ctx context.Context, exec dbtx.DBTX, u *models.User) error
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	FindByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	ActivateUser(ctx context.Context, userID uuid.UUID) error
}
