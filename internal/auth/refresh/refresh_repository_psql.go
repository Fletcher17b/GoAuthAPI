package refresh

import (
	"context"
	"database/sql"
	"time"

	"AuthAPI/main/internal/auth/dbtx"
	"AuthAPI/main/internal/models"

	"github.com/google/uuid"
)

type refreshPostgresRepo struct {
	db dbtx.DBTX
}

func NewPostgresRefreshRepo(db *sql.DB) RefreshTokenRepository {
	return &refreshPostgresRepo{db}
}

func (r *refreshPostgresRepo) Create(ctx context.Context, t *models.RefreshToken) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO refresh_tokens (
			token_id, user_id, token_hash, client_id,
			family_id, ptoken_id, expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		t.ID, t.UserID, t.TokenHash, t.ClientID,
		t.FamilyID, nullableUUID(t.ParentToken), t.ExpiresAt, t.CreatedAt,
	)
	return err
}

func (r *refreshPostgresRepo) CreateTx(ctx context.Context, exec dbtx.DBTX, t *models.RefreshToken) error {
	_, err := exec.ExecContext(ctx, `
		INSERT INTO refresh_tokens (
			token_id, user_id, token_hash, client_id,
			family_id, ptoken_id, expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		t.ID, t.UserID, t.TokenHash, t.ClientID,
		t.FamilyID, nullableUUID(t.ParentToken), t.ExpiresAt, t.CreatedAt,
	)
	return err
}

func (r *refreshPostgresRepo) FindbyHash(ctx context.Context, exec dbtx.DBTX, hash string) (*models.RefreshToken, error) {
	var t models.RefreshToken
	var parent sql.NullString
	row := exec.QueryRowContext(ctx, `
		SELECT token_id, user_id, token_hash, client_id,
		       family_id, ptoken_id, expires_at, revoked_at, created_at
		FROM refresh_tokens
		WHERE token_hash = $1`,
		hash,
	)
	if err := row.Scan(
		&t.ID, &t.UserID, &t.TokenHash, &t.ClientID,
		&t.FamilyID, &parent, &t.ExpiresAt, &t.RevokedAt, &t.CreatedAt,
	); err != nil {
		return nil, err
	}
	if parent.Valid {
		t.ParentToken = uuid.MustParse(parent.String)
	}
	return &t, nil
}

func (r *refreshPostgresRepo) FindValidByHash(ctx context.Context, hash string) (*models.RefreshToken, error) {
	var t models.RefreshToken
	var parent sql.NullString
	row := r.db.QueryRowContext(ctx, `
		SELECT token_id, user_id, token_hash, client_id,
		       family_id, ptoken_id, expires_at, revoked_at, created_at
		FROM refresh_tokens
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		  AND expires_at > now()`,
		hash,
	)
	if err := row.Scan(
		&t.ID, &t.UserID, &t.TokenHash, &t.ClientID,
		&t.FamilyID, &parent, &t.ExpiresAt, &t.RevokedAt, &t.CreatedAt,
	); err != nil {
		return nil, err
	}
	if parent.Valid {
		t.ParentToken = uuid.MustParse(parent.String)
	}
	return &t, nil
}

func (r *refreshPostgresRepo) Revoke(ctx context.Context, exec dbtx.DBTX, tokenID uuid.UUID) error {
	_, err := exec.ExecContext(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = $1
		WHERE token_id = $2`,
		time.Now(), tokenID,
	)
	return err
}

func (r *refreshPostgresRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = CURRENT_TIMESTAMP
		WHERE user_id = $1
		  AND revoked_at IS NULL`,
		userID,
	)
	return err
}

func (r *refreshPostgresRepo) RevokeAllForFamily(ctx context.Context, exec dbtx.DBTX, familyID uuid.UUID) error {
	_, err := exec.ExecContext(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = CURRENT_TIMESTAMP
		WHERE family_id = $1
		  AND revoked_at IS NULL`,
		familyID,
	)
	return err
}
