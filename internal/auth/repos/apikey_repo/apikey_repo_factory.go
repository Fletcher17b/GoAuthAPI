package apikeyrepo

import "database/sql"

func NewApiKeyRepo(driver string, db *sql.DB) ApiKeyRepository {
	switch driver {
	case "sqlite":
		panic("unsupported database driver")
	case "postgres":
		return NewPostgresApiKeyRepo()
	default:
		panic("unsupported database driver")
	}
}
