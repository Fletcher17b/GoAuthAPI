package db

import (
	"database/sql"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func runMigrationDirectory(db *sql.DB, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	var migrations []fs.DirEntry

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if strings.HasSuffix(entry.Name(), ".sql") {
			migrations = append(migrations, entry)
		}
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Name() < migrations[j].Name()
	})

	tx, err := db.Begin()
	if err != nil {
		return err
	}

	defer tx.Rollback()

	for _, migration := range migrations {
		path := filepath.Join(dir, migration.Name())

		log.Printf("Running migration %s", migration.Name())

		sqlBytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		if _, err := tx.Exec(string(sqlBytes)); err != nil {
			return fmt.Errorf("%s: %w", migration.Name(), err)
		}
	}

	return tx.Commit()
}

func RunMigrations(db *sql.DB, driver string) error {
	var dir string

	switch driver {
	case "sqlite":
		dir = "./migrations/sqlite"

	case "postgres":
		dir = "./migrations/postgres"

	default:
		return fmt.Errorf("unsupported database driver %q", driver)
	}

	return runMigrationDirectory(db, dir)
}
