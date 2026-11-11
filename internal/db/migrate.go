package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// Records which migration files have already been applied.
	migrationsTable = "schema_migrations"

	// Arbitrary constant. Every instance of the app must use the same value so
	// that two instances starting at once don't run migrations concurrently.
	migrationsLockKey int64 = 7263548102
)

func ExecuteMigrations(db *sql.DB, dirPath string, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	ctx := context.Background()

	logger.Info("starting database migrations", "directory", dirPath)

	files, err := listMigrationFiles(dirPath)
	if err != nil {
		logger.Error("failed to read migration directory", "directory", dirPath, "error", err)
		return err
	}

	// The advisory lock is per-connection, so pin one connection for the whole run.
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquiring connection for migrations: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationsLockKey); err != nil {
		return fmt.Errorf("acquiring migration lock: %w", err)
	}
	defer func() {
		if _, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationsLockKey); err != nil {
			logger.Warn("failed to release migration lock", "error", err)
		}
	}()

	if _, err := conn.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS `+migrationsTable+` (
			filename   TEXT PRIMARY KEY,
			checksum   TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`); err != nil {
		return explain(fmt.Errorf("creating %s table: %w", migrationsTable, err))
	}

	applied, err := loadApplied(ctx, conn)
	if err != nil {
		return err
	}

	var ran, skipped int
	for _, name := range files {
		path := filepath.Join(dirPath, name)

		logger.Debug("reading migration file", "file", path)
		content, err := os.ReadFile(path)
		if err != nil {
			logger.Error("failed to read migration file", "file", name, "error", err)
			return fmt.Errorf("reading migration %s: %w", path, err)
		}
		sum := checksum(content)

		if prev, ok := applied[name]; ok {
			if prev != sum {
				logger.Warn("applied migration was modified after being applied; it will NOT be re-run",
					"file", name)
			}
			logger.Debug("skipping already applied migration", "file", name)
			skipped++
			continue
		}

		logger.Info("executing migration", "file", name)
		if err := applyMigration(ctx, conn, name, string(content), sum); err != nil {
			logger.Error("failed to execute migration", "file", name, "error", err)
			return explain(fmt.Errorf("executing migration %s: %w", name, err))
		}
		logger.Info("successfully executed migration", "file", name)
		ran++
	}

	logger.Info("all migrations completed successfully", "applied", ran, "skipped", skipped, "total", len(files))
	return nil
}

func listMigrationFiles(dirPath string) ([]string, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("reading migration directory %s: %w", dirPath, err)
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".sql" {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	return files, nil
}

func loadApplied(ctx context.Context, conn *sql.Conn) (map[string]string, error) {
	rows, err := conn.QueryContext(ctx, `SELECT filename, checksum FROM `+migrationsTable)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", migrationsTable, err)
	}
	defer rows.Close()

	applied := make(map[string]string)
	for rows.Next() {
		var name, sum string
		if err := rows.Scan(&name, &sum); err != nil {
			return nil, fmt.Errorf("scanning %s: %w", migrationsTable, err)
		}
		applied[name] = sum
	}
	return applied, rows.Err()
}

func applyMigration(ctx context.Context, conn *sql.Conn, name, query, sum string) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, query); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO `+migrationsTable+` (filename, checksum) VALUES ($1, $2)`,
		name, sum,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func checksum(content []byte) string {
	// Normalize line endings so CRLF/LF checkouts of the same file hash the same.
	normalized := strings.ReplaceAll(string(content), "\r\n", "\n")
	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:])
}

func explain(err error) error {
	if strings.Contains(err.Error(), "3F000") {
		return fmt.Errorf("%w \n (hint: the connected role probably lacks USAGE/CREATE on schema public; "+
			"run `GRANT USAGE, CREATE ON SCHEMA public TO <role>;` as a superuser)", err)
	}
	return err
}
