package mail

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"AuthAPI/main/internal/models"
)

type EmailVerificationPostgresRepo struct {
	db *sql.DB
}

func NewEmailVerificationPostgresRepo(db *sql.DB) EmailVerificationRepository {
	return &EmailVerificationPostgresRepo{db: db}
}

func (r *EmailVerificationPostgresRepo) Create(ctx context.Context, t *models.EmailVerificationToken) error {
	_, err := r.db.ExecContext(
		ctx,
		`INSERT INTO email_verification_tokens
		 (token_id, user_id, token_hash, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		t.ID,
		t.UserID,
		t.TokenHash,
		t.ExpiresAt,
		t.CreatedAt,
	)
	return err
}

func (r *EmailVerificationPostgresRepo) FindValidByHash(ctx context.Context, hash string) (*models.EmailVerificationToken, error) {
	row := r.db.QueryRowContext(
		ctx,
		`SELECT token_id, user_id, token_hash, expires_at, used_at, created_at
		 FROM email_verification_tokens
		 WHERE token_hash = $1
		   AND used_at IS NULL
		   AND expires_at > CURRENT_TIMESTAMP`,
		hash,
	)

	var t models.EmailVerificationToken
	if err := row.Scan(
		&t.ID,
		&t.UserID,
		&t.TokenHash,
		&t.ExpiresAt,
		&t.UsedAt,
		&t.CreatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("invalid token")
		}
		return nil, err
	}

	return &t, nil
}

func (r *EmailVerificationPostgresRepo) MarkUsed(ctx context.Context, tokenID string, usedAt time.Time) error {
	_, err := r.db.ExecContext(
		ctx,
		`UPDATE email_verification_tokens
		 SET used_at = $1
		 WHERE token_id = $2`,
		usedAt,
		tokenID,
	)
	return err
}

func (r *EmailVerificationPostgresRepo) DeleteAllForUser(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(
		ctx,
		`DELETE FROM email_verification_tokens
		 WHERE user_id = $1`,
		userID,
	)
	return err
}

func (r *EmailVerificationPostgresRepo) DeleteByUserID(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(
		ctx,
		`DELETE FROM email_verification_tokens
		 WHERE user_id = $1`,
		userID,
	)
	return err
}
