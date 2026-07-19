package mail

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"AuthAPI/main/internal/models"

	"github.com/google/uuid"
)

type EmailVerificationSQLiteRepo struct {
	db *sql.DB
}

func NewEmailVerificationSQLiteRepo(db *sql.DB) EmailVerificationRepository {
	return &EmailVerificationSQLiteRepo{db: db}
}

func (r *EmailVerificationSQLiteRepo) Create(ctx context.Context, t *models.EmailVerificationToken) error {
	_, err := r.db.ExecContext(
		ctx,
		`INSERT INTO email_verification_tokens
		 (token_id, user_id, token_hash, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		t.ID,
		t.UserID,
		t.TokenHash,
		t.ExpiresAt,
		t.CreatedAt,
	)
	return err
}

func (r *EmailVerificationSQLiteRepo) FindValidByHash(ctx context.Context, hash string) (*models.EmailVerificationToken, error) {
	row := r.db.QueryRowContext(
		ctx,
		`SELECT token_id, user_id, token_hash, expires_at, used_at, created_at
		 FROM email_verification_tokens
		 WHERE token_hash = ?
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

func (r *EmailVerificationSQLiteRepo) MarkUsed(ctx context.Context, tokenID uuid.UUID, usedAt time.Time) error {
	_, err := r.db.ExecContext(
		ctx,
		`UPDATE email_verification_tokens
		 SET used_at = ?
		 WHERE token_id = ?`,
		usedAt,
		tokenID,
	)
	return err
}

func (r *EmailVerificationSQLiteRepo) DeleteAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.ExecContext(
		ctx,
		`DELETE FROM email_verification_tokens WHERE user_id = ?`,
		userID,
	)
	return err
}

func (r *EmailVerificationSQLiteRepo) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.ExecContext(
		ctx,
		`DELETE FROM email_verification_tokens WHERE user_id = ?`,
		userID,
	)
	return err
}
