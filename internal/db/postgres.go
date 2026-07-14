package db

import (
	"AuthAPI/main/internal/config"
	"database/sql"
	"fmt"
)

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
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host,
		cfg.Port,
		cfg.User,
		cfg.Password,
		cfg.Database,
		cfg.SSLMode,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}

	/* ok, err := postgresSchemaExists(db)
	if err != nil {
		db.Close()
		return nil, err
	} */

	/* if !ok {
			db.Close()
			return nil, fmt.Errorf(
				`postgres database is reachable but has no application schema.
	Run the PostgreSQL migrations before starting the service`,
			)
		} */

	return db, nil
}
