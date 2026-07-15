package db

import (
	"AuthAPI/main/internal/config"
	"database/sql"
	"fmt"
)

func Open(cfg config.DatabaseConfig) (*sql.DB, error) {
	switch cfg.Driver {
	case "sqlite":
		return OpenSQLite(cfg.SqliteConf.Path)

	case "postgres":
		return OpenPostgres(cfg.PostgresConf)

	default:
		return nil, fmt.Errorf("unsupported database driver %q", cfg.Driver)
	}
}
