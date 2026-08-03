package db

import (
	"AuthAPI/main/internal/config"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func RunPostgresMigrations(db *sql.DB) error {
	return executeMigration(
		db,
		"./migrations/postgres/001_init.sql",
	)
}

//nolint:unused
func postgresSchemaExists(db *sql.DB) (bool, error) {
	var exists bool

	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.tables
			WHERE table_schema = 'public'
			  AND table_name = 'users'
		)
	`).Scan(&exists)

	if err != nil {
		return false, err
	}

	return exists, nil
}

func OpenPostgres(cfg config.PostgresConfig) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s",
		cfg.Host,
		cfg.Port,
		cfg.User,
		cfg.Password,
		cfg.Database,
		/* cfg.SSLMode, */
	)

	var db *sql.DB
	var err error

	maxTries := 5
	backoff := 1 * time.Second

	for attempt := 1; attempt <= maxTries; attempt++ {
		db, err = sql.Open("pgx/v5", dsn)
		if err == nil {
			err = db.Ping()
			if err == nil {
				break
			}
		}
		if db != nil {
			_ = db.Close()
		}

		if attempt == maxTries {
			return nil, fmt.Errorf("failed to connect to database after %d attempts: %w", maxTries, err)
		}
		time.Sleep(backoff)
	}

	if err := RunPostgresMigrations(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return db, nil
}
