package users

import (
	"context"
	"database/sql"
	"errors"

	"AuthAPI/main/internal/auth/dbtx"
	"AuthAPI/main/internal/models"

	"github.com/google/uuid"
)

type sqliteRepo struct {
	db dbtx.DBTX
}

func NewSQLiteRepository(db *sql.DB) Repository {
	return &sqliteRepo{db}
}

func (r *sqliteRepo) Create(ctx context.Context, u *models.User) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO users (
			user_id, email, username, password_hash,
			email_verified, is_active, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.Username, u.PasswordHash,
		u.EmailVerified, u.IsActive,
		u.CreatedAt, u.UpdatedAt,
	)
	return err
}

func (r *sqliteRepo) CreateTx(ctx context.Context, exec dbtx.DBTX, u *models.User) error {
	_, err := exec.ExecContext(ctx, `
		INSERT INTO users (
			user_id, email, username, password_hash,
			email_verified, is_active, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.Username, u.PasswordHash,
		u.EmailVerified, u.IsActive,
		u.CreatedAt, u.UpdatedAt,
	)
	return err
}

func (r *sqliteRepo) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT user_id, email, username, password_hash,
		       email_verified, is_active, created_at, updated_at
		FROM users WHERE email = ?`, email)

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

func (r *sqliteRepo) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT user_id, email, username, password_hash,
		       email_verified, is_active, created_at, updated_at
		FROM users WHERE user_id = ?`, id)

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

func (r *sqliteRepo) ActivateUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.ExecContext(
		ctx,
		`UPDATE users
		 SET is_active = 1, updated_at = CURRENT_TIMESTAMP
		 WHERE user_id = ?`,
		userID,
	)

	if err == nil {
		_, err_2 := r.db.ExecContext(
			ctx,
			`UPDATE users
		 SET email_verified = 1, updated_at = CURRENT_TIMESTAMP
		 WHERE user_id = ?`,
			userID,
		)
		return err_2

	}

	return err
}
