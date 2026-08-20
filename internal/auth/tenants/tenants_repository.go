package tenants

import (
	"context"
	"database/sql"

	"AuthAPI/main/internal/models"
)

// Repository provides read access to tenants for request-time resolution.
// Write operations (provisioning new tenants, rotating API keys, etc.) are
// deliberately out of scope for now per the staged rollout - see the
// public_key/api_key_hash fields on models.Tenant, left for a later stage.
type TenantRepository interface {
	FindByTenantName(ctx context.Context, tenantName string) (*models.Tenant, error)
	FindByID(ctx context.Context, id string) (*models.Tenant, error)
}

func NewTenantRepo(driver string, db *sql.DB) TenantRepository {
	switch driver {
	case "sqlite":
		sqlite_repo := NewSQLiteRepository(db)

		if sqlite_repo == nil {
			panic("Unable to Spin up EmailVerification Repository")
		}
		return sqlite_repo
	case "postgres":
		psql_repo := NewPostgresRepository(db)
		if psql_repo == nil {
			panic("Unable to Spin up EmailVerification Repository")
		}

		return psql_repo
	default:
		panic("unsupported database driver")
	}
}
