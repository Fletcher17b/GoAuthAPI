package db

import (
	"database/sql"
	"fmt"
	"os"
)

func executeMigration(db *sql.DB, path string) error {
	migration, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading migration %s: %w", path, err)
	}

	if _, err := db.Exec(string(migration)); err != nil {
		return fmt.Errorf("executing migration %s: %w", path, err)
	}

	return nil
}
