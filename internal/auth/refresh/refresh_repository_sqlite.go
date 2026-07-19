package refresh

import (
	"context"
	"database/sql"
	"time"

	"AuthAPI/main/internal/auth/dbtx"
	"AuthAPI/main/internal/models"

	"github.com/google/uuid"
)

type refreshRepo struct {
	db dbtx.DBTX
}

func NewSqliteRefreshRepo(db *sql.DB) RefreshTokenRepository {
	return &refreshRepo{db}
}

func (r *refreshRepo) Create(ctx context.Context, t *models.RefreshToken) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO refresh_tokens (
			token_id, user_id, token_hash, client_id,
			expires_at, created_at
		) VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, t.UserID, t.TokenHash, t.ClientID,
		t.ExpiresAt, t.CreatedAt,
	)
	return err
}

func (r *refreshRepo) CreateTx(ctx context.Context, exec dbtx.DBTX, t *models.RefreshToken) error {
	_, err := exec.ExecContext(ctx, `
		INSERT INTO refresh_tokens (
			token_id, user_id, token_hash, client_id,
			expires_at, created_at
		) VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, t.UserID, t.TokenHash, t.ClientID,
		t.ExpiresAt, t.CreatedAt,
	)
	return err
}

func (r *refreshRepo) FindValidByHash(ctx context.Context, hash string) (*models.RefreshToken, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT token_id, user_id, token_hash,
		       expires_at, revoked_at, created_at
		FROM refresh_tokens
		WHERE token_hash = ?
		  AND revoked_at IS NULL
		  AND expires_at > ?`,
		hash, time.Now(),
	)

	var t models.RefreshToken
	if err := row.Scan(
		&t.ID, &t.UserID, &t.TokenHash,
		&t.ExpiresAt, &t.RevokedAt, &t.CreatedAt,
	); err != nil {
		return nil, err
	}

	return &t, nil
}

func (r *refreshRepo) Revoke(ctx context.Context, tokenID uuid.UUID) error {
	now := time.Now()
	_, err := r.db.ExecContext(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = ?
		WHERE token_id = ?`,
		now, tokenID,
	)
	return err
}

func (r *refreshRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = CURRENT_TIMESTAMP
		WHERE user_id = ?
		  AND revoked_at IS NULL
	`, userID)
	return err
}
