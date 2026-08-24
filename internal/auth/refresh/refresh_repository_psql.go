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
			token_id,
			user_id,
			token_hash,
			client_id,
			family_id,
			ptoken_id,
			expires_at,
			created_at,
			tenant_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		t.ID,
		t.UserID,
		t.TokenHash,
		t.ClientID,
		t.FamilyID,
		nullableUUID(t.ParentToken),
		t.ExpiresAt,
		t.CreatedAt,
		t.TenantID,
	)
	return err
}

func (r *refreshPostgresRepo) CreateTx(ctx context.Context, exec dbtx.DBTX, t *models.RefreshToken) error {
	_, err := exec.ExecContext(ctx, `
		INSERT INTO refresh_tokens (
			token_id,
			user_id,
			token_hash,
			client_id,
			family_id,
			ptoken_id,
			expires_at,
			created_at,
			tenant_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		t.ID,
		t.UserID,
		t.TokenHash,
		t.ClientID,
		t.FamilyID,
		nullableUUID(t.ParentToken),
		t.ExpiresAt,
		t.CreatedAt,
		t.TenantID,
	)
	return err
}

func (r *refreshPostgresRepo) FindbyHash(
	ctx context.Context,
	exec dbtx.DBTX,
	hash string,
	tenant uuid.UUID,
) (*models.RefreshToken, error) {
	var t models.RefreshToken
	var parent sql.NullString

	row := exec.QueryRowContext(ctx, `
		SELECT
			token_id,
			user_id,
			token_hash,
			client_id,
			family_id,
			ptoken_id,
			expires_at,
			revoked_at,
			created_at
		FROM refresh_tokens
		WHERE token_hash = $1
		  AND tenant_id = $2`,
		hash,
		tenant,
	)

	if err := row.Scan(
		&t.ID,
		&t.UserID,
		&t.TokenHash,
		&t.ClientID,
		&t.FamilyID,
		&parent,
		&t.ExpiresAt,
		&t.RevokedAt,
		&t.CreatedAt,
	); err != nil {
		return nil, err
	}

	if parent.Valid {
		t.ParentToken = uuid.MustParse(parent.String)
	}

	return &t, nil
}

func (r *refreshPostgresRepo) FindValidByHash(
	ctx context.Context,
	hash string,
	tenant uuid.UUID,
) (*models.RefreshToken, error) {
	var t models.RefreshToken
	var parent sql.NullString

	row := r.db.QueryRowContext(ctx, `
		SELECT
			token_id,
			user_id,
			token_hash,
			client_id,
			family_id,
			ptoken_id,
			expires_at,
			revoked_at,
			created_at
		FROM refresh_tokens
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
		  AND tenant_id = $2`,
		hash,
		tenant,
	)

	if err := row.Scan(
		&t.ID,
		&t.UserID,
		&t.TokenHash,
		&t.ClientID,
		&t.FamilyID,
		&parent,
		&t.ExpiresAt,
		&t.RevokedAt,
		&t.CreatedAt,
	); err != nil {
		return nil, err
	}

	if parent.Valid {
		t.ParentToken = uuid.MustParse(parent.String)
	}

	return &t, nil
}

func (r *refreshPostgresRepo) Revoke(
	ctx context.Context,
	exec dbtx.DBTX,
	tokenID uuid.UUID,
	tenant uuid.UUID,
) error {
	_, err := exec.ExecContext(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = $1
		WHERE token_id = $2
		  AND tenant_id = $3`,
		time.Now(),
		tokenID,
		tenant,
	)

	return err
}

func (r *refreshPostgresRepo) RevokeAllForUser(
	ctx context.Context,
	userID uuid.UUID,
	tenant uuid.UUID,
) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = CURRENT_TIMESTAMP
		WHERE user_id = $1
		  AND revoked_at IS NULL
		  AND tenant_id = $2`,
		userID,
		tenant,
	)

	return err
}

func (r *refreshPostgresRepo) RevokeAllForFamily(
	ctx context.Context,
	exec dbtx.DBTX,
	familyID uuid.UUID,
	tenant uuid.UUID,
) error {
	_, err := exec.ExecContext(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = CURRENT_TIMESTAMP
		WHERE family_id = $1
		  AND revoked_at IS NULL
		  AND tenant_id = $2`,
		familyID,
		tenant,
	)

	return err
}

func (r *refreshPostgresRepo) CreateResetTokenTx(
	ctx context.Context,
	exec dbtx.DBTX,
	rtkn models.PasswordResetToken,
) error {
	_, err := exec.ExecContext(ctx, `
		INSERT INTO password_reset_tokens (
			token_id,
			user_id,
			tenant_id,
			token_hash,
			expires_at,
			created_at
		) VALUES ($1, $2, $3, $4, $5, $6)`,
		rtkn.ID,
		rtkn.UserID,
		rtkn.TenantID,
		rtkn.TokenHash,
		rtkn.ExpiresAt,
		rtkn.CreatedAt,
	)

	return err
}

func (r *refreshPostgresRepo) FindValidResetTokenTx(
	ctx context.Context,
	exec dbtx.DBTX,
	hash string,
	tenant uuid.UUID,
) (*models.PasswordResetToken, error) {
	row := exec.QueryRowContext(ctx, `
		SELECT token_id, user_id, tenant_id, token_hash, expires_at, used_at, created_at
		FROM password_reset_tokens
		WHERE token_hash = $1
		  AND tenant_id = $2
		  AND used_at IS NULL
		  AND expires_at > CURRENT_TIMESTAMP`,
		hash, tenant,
	)

	var t models.PasswordResetToken
	if err := row.Scan(
		&t.ID, &t.UserID, &t.TenantID, &t.TokenHash, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *refreshPostgresRepo) MarkResetTokenUsedTx(
	ctx context.Context,
	exec dbtx.DBTX,
	tokenID uuid.UUID,
) error {
	usedAt := time.Now()
	_, err := exec.ExecContext(ctx, `
		UPDATE password_reset_tokens
		SET used_at = $1
		WHERE token_id = $2`,
		usedAt, tokenID,
	)
	return err
}
