package refresh

import (
	"context"
	"database/sql"
	"time"

	"AuthAPI/main/internal/models"
)

type refreshPostgresRepo struct {
	db *sql.DB
}

func NewPostgresRefreshRepo(db *sql.DB) RefreshTokenRepository {
	return &refreshPostgresRepo{db}
}

func (r *refreshPostgresRepo) Create(ctx context.Context, t *models.RefreshToken) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO refresh_tokens (
			token_id, user_id, token_hash, client_id,
			expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6)`,
		t.ID, t.UserID, t.TokenHash, t.ClientID,
		t.ExpiresAt, t.CreatedAt,
	)
	return err
}

func (r *refreshPostgresRepo) FindValidByHash(ctx context.Context, hash string) (*models.RefreshToken, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT token_id, user_id, token_hash,
		       expires_at, revoked_at, created_at
		FROM refresh_tokens
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		  AND expires_at > $2`,
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

func (r *refreshPostgresRepo) Revoke(ctx context.Context, tokenID string) error {
	now := time.Now()

	_, err := r.db.ExecContext(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = $1
		WHERE token_id = $2`,
		now, tokenID,
	)

	return err
}

func (r *refreshPostgresRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = CURRENT_TIMESTAMP
		WHERE user_id = $1
		  AND revoked_at IS NULL`,
		userID,
	)

	return err
}
