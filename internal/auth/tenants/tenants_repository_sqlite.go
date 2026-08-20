package tenants

import (
	"context"
	"database/sql"
	"encoding/json"

	"AuthAPI/main/internal/models"
)

type sqliteRepo struct {
	db *sql.DB
}

func NewSQLiteRepository(db *sql.DB) TenantRepository {
	return &sqliteRepo{db}
}

func (r *sqliteRepo) FindByTenantName(ctx context.Context, tenantName string) (*models.Tenant, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT tenant_id, tenant_name, name, url, email, status,
		       public_key, api_key_hash, allowed_origins,
		       created_at, updated_at
		FROM tenants
		WHERE tenant_name = ?`,
		tenantName,
	)
	return scanSQLiteTenant(row)
}

func (r *sqliteRepo) FindByID(ctx context.Context, id string) (*models.Tenant, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT tenant_id, tenant_name, name, url, email, status,
		       public_key, api_key_hash, allowed_origins,
		       created_at, updated_at
		FROM tenants
		WHERE tenant_id = ?`,
		id,
	)
	return scanSQLiteTenant(row)
}

func scanSQLiteTenant(row row) (*models.Tenant, error) {
	var t models.Tenant
	var status string
	var name sql.NullString
	var allowedOriginsRaw sql.NullString

	if err := row.Scan(
		&t.ID, &t.TenantName, &name, &t.URL, &t.Email, &status,
		&t.PublicKey, &t.APIKeyHash, &allowedOriginsRaw,
		&t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return nil, err
	}

	t.Name = name.String
	t.Status = models.TenantStatus(status)

	if allowedOriginsRaw.Valid && allowedOriginsRaw.String != "" {
		if err := json.Unmarshal([]byte(allowedOriginsRaw.String), &t.AllowedOrigins); err != nil {
			return nil, err
		}
	}

	return &t, nil
}
