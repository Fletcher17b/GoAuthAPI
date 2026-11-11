package apikeyrepo

import (
	"AuthAPI/main/internal/auth/dbtx"
	"AuthAPI/main/internal/models"
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type apikeyPostgresRepo struct{}

func NewPostgresApiKeyRepo() ApiKeyRepository {
	return &apikeyPostgresRepo{}
}

func (r *apikeyPostgresRepo) CreateTx(ctx context.Context, exec dbtx.DBTX, t *models.Apikey_model) error {
	_, err := exec.ExecContext(ctx, `
		INSERT INTO apikeys (
			apikey_id,
			apikeyowner_id,
			apikey_hash,
			name,
			revoked,
			expires_at,
			created_at
		) VALUES ($1, $2, $3, $4, FALSE, $5, $6)`,
		t.Apikey_ID,
		t.KeyOwner,
		t.Keyhash,
		t.Keyname,
		t.ExpiresAt,
		t.CreatedAt,
	)
	return err
}

func (r *apikeyPostgresRepo) UpdateTx(ctx context.Context, exec dbtx.DBTX, t *models.Apikey_model) error {
	res, err := exec.ExecContext(ctx, `
		UPDATE apikeys
		SET name = $1, expires_at = $2
		WHERE apikey_id = $3 AND apikeyowner_id = $4 AND revoked = FALSE`,
		t.Keyname,
		t.ExpiresAt,
		t.Apikey_ID,
		t.KeyOwner,
	)
	return expectOne(res, err)
}

func (r *apikeyPostgresRepo) FindbyHash(ctx context.Context, exec dbtx.DBTX, hash string, consumerID uuid.UUID) (*models.Apikey_model, error) {
	var k models.Apikey_model
	var name sql.NullString
	var revokedAt sql.NullTime

	err := exec.QueryRowContext(ctx, `
		SELECT apikey_id, apikeyowner_id, apikey_hash, name,
		       revoked, revoked_at, expires_at, created_at
		FROM apikeys
		WHERE apikey_hash = $1
		  AND apikeyowner_id = $2
		  AND revoked = FALSE
		  AND expires_at > $3`,
		hash,
		consumerID,
		time.Now().UTC(),
	).Scan(
		&k.Apikey_ID, &k.KeyOwner, &k.Keyhash, &name,
		&k.Revoked, &revokedAt, &k.ExpiresAt, &k.CreatedAt,
	)
	if err != nil {
		return nil, err // sql.ErrNoRows if missing, revoked or expired
	}

	k.Keyname = name.String
	if revokedAt.Valid {
		k.RevokedAt = &revokedAt.Time
	}
	return &k, nil
}

// RegisterUse is a no-op until the table gets a last_used_at column.
// Stub, pendent defining
func (r *apikeyPostgresRepo) RegisterUse(ctx context.Context, exec dbtx.DBTX, apikeyID uuid.UUID) error {
	return nil
}

func (r *apikeyPostgresRepo) Revoke(ctx context.Context, exec dbtx.DBTX, apikeyID uuid.UUID, consumerID uuid.UUID) error {
	res, err := exec.ExecContext(ctx, `
		UPDATE apikeys
		SET revoked = TRUE, revoked_at = $1
		WHERE apikey_id = $2 AND apikeyowner_id = $3 AND revoked = FALSE`,
		time.Now().UTC(),
		apikeyID,
		consumerID,
	)
	return expectOne(res, err)
}

func expectOne(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
