package users

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"AuthAPI/main/internal/auth/dbtx"
	"AuthAPI/main/internal/models"

	"github.com/google/uuid"
)

type postgresRepo struct {
	db dbtx.DBTX
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

func (r *postgresRepo) CreateTx(ctx context.Context, exec dbtx.DBTX, u *models.User) error {
	_, err := exec.ExecContext(ctx, `
		INSERT INTO users (
			user_id, email, username, password_hash,
			email_verified, is_active, created_at, updated_at,
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
		&u.CreatedAt, &u.UpdatedAt, &u.LockedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
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
		&u.CreatedAt, &u.UpdatedAt, &u.LockedAt,
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
		     email_verified = TRUE,
		     updated_at = $1
		 WHERE user_id = $2`,
		time.Now(),
		userID,
	)

	return err
}

/*
Recieves the user id and a bool
if the bool is true it sets locked_at column in users table to a
time stamp, marking that user as locked out and unable to log in

if the bool is false it sets the locked_at column in users table
to NULL (go converts empty pointer (nil) to SQL NULL) marking it
free to log in

works by the conditional:

	if user.LockedAt == nil {do stuff} else {permission denied}
	if
*/
func (r *postgresRepo) LockoutUser(ctx context.Context, exec dbtx.DBTX, user uuid.UUID, lock bool) error {
	var lockedAt *time.Time

	if lock {
		now := time.Now()
		lockedAt = &now
	}

	_, err := exec.ExecContext(ctx, `
		UPDATE users
		SET locked_at = $1
		WHERE user_id = $2`,
		lockedAt,
		user,
	)

	return err
}

func (r *postgresRepo) ChangePasword(ctx context.Context, exec dbtx.DBTX, user uuid.UUID, new_password string) error {
	_, err := exec.ExecContext(ctx, `
		UPDATE users
		SET password_hash = $1
		WHERE user_id = $2`,
		new_password,
		user,
	)

	return err
}
