package tenants

import (
	"context"
	"database/sql"
	"encoding/json"

	"AuthAPI/main/internal/models"
)

type postgresRepo struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) TenantRepository {
	return &postgresRepo{db}
}

func (r *postgresRepo) FindByTenantName(ctx context.Context, tenantName string) (*models.Tenant, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT tenant_id, tenant_name, name, url, email, status,
		       public_key, api_key_hash, allowed_origins,
		       created_at, updated_at
		FROM tenants
		WHERE tenant_name = $1`,
		tenantName,
	)
	return scanTenant(row)
}

func (r *postgresRepo) FindByID(ctx context.Context, id string) (*models.Tenant, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT tenant_id, tenant_name, name, url, email, status,
		       public_key, api_key_hash, allowed_origins,
		       created_at, updated_at
		FROM tenants
		WHERE tenant_id = $1`,
		id,
	)
	return scanTenant(row)
}

type row interface {
	Scan(dest ...any) error
}

func scanTenant(row row) (*models.Tenant, error) {
	var t models.Tenant
	var status string
	var name sql.NullString
	var allowedOriginsRaw []byte

	if err := row.Scan(
		&t.ID, &t.TenantName, &name, &t.URL, &t.Email, &status,
		&t.PublicKey, &t.APIKeyHash, &allowedOriginsRaw,
		&t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return nil, err
	}

	t.Name = name.String
	t.Status = models.TenantStatus(status)

	if len(allowedOriginsRaw) > 0 {
		if err := json.Unmarshal(allowedOriginsRaw, &t.AllowedOrigins); err != nil {
			return nil, err
		}
	}

	return &t, nil
}
