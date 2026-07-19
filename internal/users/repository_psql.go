package users

import (
	"context"
	"database/sql"
	"errors"

	"AuthAPI/main/internal/models"

	"github.com/google/uuid"
)

type postgresRepo struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) Repository {
	return &postgresRepo{db}
}

func (r *postgresRepo) Create(ctx context.Context, u *models.User) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO users (
			user_id, email, username, password_hash,
			email_verified, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		u.ID, u.Email, u.Username, u.PasswordHash,
		u.EmailVerified, u.IsActive,
		u.CreatedAt, u.UpdatedAt,
	)
	return err
}

func (r *postgresRepo) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT user_id, email, username, password_hash,
		       email_verified, is_active, created_at, updated_at
		FROM users
		WHERE email = $1`,
		email,
	)

	var u models.User
	if err := row.Scan(
		&u.ID, &u.Email, &u.Username, &u.PasswordHash,
		&u.EmailVerified, &u.IsActive,
		&u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &u, nil
}

func (r *postgresRepo) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT user_id, email, username, password_hash,
		       email_verified, is_active, created_at, updated_at
		FROM users
		WHERE user_id = $1`,
		id,
	)

	var u models.User
	if err := row.Scan(
		&u.ID, &u.Email, &u.Username, &u.PasswordHash,
		&u.EmailVerified, &u.IsActive,
		&u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		return nil, err
	}

	return &u, nil
}

func (r *postgresRepo) ActivateUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.ExecContext(
		ctx,
		`UPDATE users
		 SET is_active = TRUE,
		     updated_at = CURRENT_TIMESTAMP
		 WHERE user_id = $1`,
		userID,
	)

	if err != nil {
		return err
	}

	_, err = r.db.ExecContext(
		ctx,
		`UPDATE users
		 SET email_verified = TRUE,
		     updated_at = CURRENT_TIMESTAMP
		 WHERE user_id = $1`,
		userID,
	)

	return err
}
