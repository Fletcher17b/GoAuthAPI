package db

import (
	"database/sql"
	"os"
)

func RunMigrations(db *sql.DB, path string) error {
	migration, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	_, err = db.Exec(string(migration))
	return err
}
