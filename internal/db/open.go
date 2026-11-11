package db

import (
	"AuthAPI/main/internal/config"
	"database/sql"
	"fmt"
	"log/slog"
)

func Open(cfg config.DatabaseConfig, logger *slog.Logger) (*sql.DB, error) {
	switch cfg.Driver {
	case "sqlite":
		return OpenSQLite(cfg.SqliteConf.Path)

	case "postgres":
		return OpenPostgres(cfg.PostgresConf, logger)

	default:
		return nil, fmt.Errorf("unsupported database driver %q", cfg.Driver)
	}
}
