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
	return &postgresRepo{db: db}
}

func (r *postgresRepo) Create(ctx context.Context, u *models.User) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO users (
			user_id,
			email,
			username,
			password_hash,
			email_verified,
			is_active,
			created_at,
			updated_at,
			tenant_id
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`,
		u.ID,
		u.Email,
		u.Username,
		u.PasswordHash,
		u.EmailVerified,
		u.IsActive,
		u.CreatedAt,
		u.UpdatedAt,
		u.Tenant_ID,
	)

	return err
}

func (r *postgresRepo) CreateTx(
	ctx context.Context,
	exec dbtx.DBTX,
	u *models.User,
) error {
	_, err := exec.ExecContext(ctx, `
		INSERT INTO users (
			user_id,
			email,
			username,
			password_hash,
			email_verified,
			is_active,
			created_at,
			updated_at,
			tenant_id
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`,
		u.ID,
		u.Email,
		u.Username,
		u.PasswordHash,
		u.EmailVerified,
		u.IsActive,
		u.CreatedAt,
		u.UpdatedAt,
		u.Tenant_ID,
	)

	return err
}

func (r *postgresRepo) FindByEmail(
	ctx context.Context,
	email string,
	tenant uuid.UUID,
) (*models.User, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT
			user_id,
			email,
			username,
			password_hash,
			email_verified,
			is_active,
			created_at,
			updated_at,
			locked_at,
			tenant_id
		FROM users
		WHERE email = $1
		  AND tenant_id = $2
		LIMIT 1
	`,
		email,
		tenant,
	)

	var u models.User

	if err := row.Scan(
		&u.ID,
		&u.Email,
		&u.Username,
		&u.PasswordHash,
		&u.EmailVerified,
		&u.IsActive,
		&u.CreatedAt,
		&u.UpdatedAt,
		&u.LockedAt,
		&u.Tenant_ID,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}

		return nil, err
	}

	return &u, nil
}

func (r *postgresRepo) FindByID(
	ctx context.Context,
	id uuid.UUID,
) (*models.User, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT
			user_id,
			email,
			username,
			password_hash,
			email_verified,
			is_active,
			created_at,
			updated_at,
			locked_at,
			tenant_id
		FROM users
		WHERE user_id = $1
		LIMIT 1
	`,
		id,
	)

	var u models.User

	if err := row.Scan(
		&u.ID,
		&u.Email,
		&u.Username,
		&u.PasswordHash,
		&u.EmailVerified,
		&u.IsActive,
		&u.CreatedAt,
		&u.UpdatedAt,
		&u.LockedAt,
		&u.Tenant_ID,
	); err != nil {
		return nil, err
	}

	return &u, nil
}

func (r *postgresRepo) ActivateUser(
	ctx context.Context,
	userID uuid.UUID,
) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE users
		SET
			is_active = TRUE,
			email_verified = TRUE,
			updated_at = CURRENT_TIMESTAMP
		WHERE user_id = $1
	`,
		userID,
	)

	return err
}

func (r *postgresRepo) LockoutUser(
	ctx context.Context,
	exec dbtx.DBTX,
	userID uuid.UUID,
	lock bool,
) error {
	var lockedAt *time.Time

	if lock {
		now := time.Now()
		lockedAt = &now
	}

	_, err := exec.ExecContext(ctx, `
		UPDATE users
		SET
			locked_at = $1,
			updated_at = CURRENT_TIMESTAMP
		WHERE user_id = $2
	`,
		lockedAt,
		userID,
	)

	return err
}

func (r *postgresRepo) ChangePassword(
	ctx context.Context,
	exec dbtx.DBTX,
	userID uuid.UUID,
	newPasswordHash string,
) error {
	_, err := exec.ExecContext(ctx, `
		UPDATE users
		SET
			password_hash = $1,
			updated_at = CURRENT_TIMESTAMP
		WHERE user_id = $2
	`,
		newPasswordHash,
		userID,
	)

	return err
}
