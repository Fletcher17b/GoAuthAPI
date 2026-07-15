package db

import (
	"database/sql"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

// ex-RunMigrations(db, path)
func SqliteMigration(db *sql.DB, path string) error {
	migration, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	_, err = db.Exec(string(migration))
	return err
}

func schemaExists(db *sql.DB) (bool, error) {
	var name string

	err := db.QueryRow(`
		SELECT name
		FROM sqlite_master
		WHERE type = 'table'
		  AND name = 'users'
	`).Scan(&name)

	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}

func OpenSQLite(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}

	ok, err := schemaExists(db)
	if err != nil {
		db.Close()
		return nil, err
	}

	if !ok {
		log.Println("Creating sqlite database...")
		if err := SqliteMigration(db, "migrations/sqlite/001_init.sql"); err != nil {
			db.Close()
			return nil, err
		}
	}

	return db, nil
}
