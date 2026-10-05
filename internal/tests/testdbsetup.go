package tests

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func SetupTestDB() (db *sql.DB, reason string, teardown func()) {
	noop := func() {}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("authapi_test"),
		tcpostgres.WithUsername("authapi_test"),
		tcpostgres.WithPassword("authapi_test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		return nil, fmt.Sprintf("could not start postgres testcontainer (is Docker running?): %v", err), noop
	}

	// Single source of truth for cleanup
	cleanUp := func(db *sql.DB) {
		if db != nil {
			_ = db.Close()
		}
		_ = container.Terminate(context.Background())
	}

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		cleanUp(nil)
		return nil, fmt.Sprintf("could not get postgres connection string: %v", err), noop
	}

	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		cleanUp(nil)
		return nil, fmt.Sprintf("could not open pgx connection: %v", err), noop
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		cleanUp(sqlDB)
		return nil, fmt.Sprintf("could not ping postgres testcontainer: %v", err), noop
	}

	schema, err := os.ReadFile(migrationPath())
	if err != nil {
		cleanUp(sqlDB)
		return nil, fmt.Sprintf("could not read postgres schema file: %v", err), noop
	}

	if _, err := sqlDB.ExecContext(ctx, string(schema)); err != nil {
		cleanUp(sqlDB)
		return nil, fmt.Sprintf("could not apply postgres schema: %v", err), noop
	}

	return sqlDB, "", func() { cleanUp(sqlDB) }
}

func migrationPath() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "migrations", "postgres", "001_init.sql")
}

func RequirePostgres(t *testing.T, db *sql.DB, reason string) *sql.DB {
	t.Helper()
	if db == nil {
		t.Skipf("skipping postgres repository test: %s", reason)
	}
	return db
}
