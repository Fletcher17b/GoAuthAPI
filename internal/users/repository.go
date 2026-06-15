package users

import (
	"AuthAPI/main/internal/models"
	"context"
)

type Repository interface {
	Create(ctx context.Context, u *models.User) error
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	FindByID(ctx context.Context, id string) (*models.User, error)
	ActivateUser(ctx context.Context, userID string) error
}
