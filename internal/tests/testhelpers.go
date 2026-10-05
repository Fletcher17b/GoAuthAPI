package tests

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"testing"
	"time"

	"AuthAPI/main/internal/auth/ratelimiter"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// NoopRateLimiter satisfies ratelimiter.RedisLimiter without a live Redis
// connection: every Check passes, every Record is a no-op. Auth-flow tests
// (service/handler/E2E) use this so they don't need Redis infrastructure
// just to exercise signup/login/refresh. The rate limiter's own behavior
// — thresholds, backoff, Lua atomicity — belongs in the ratelimiter
// package's own tests, against a real Redis, not here.
type NoopRateLimiter struct{}

func (NoopRateLimiter) CheckLogin(ctx context.Context, ip, email string) error { return nil }
func (NoopRateLimiter) RecordLoginFailure(ctx context.Context, ip, email string, notifyAttempt int64) (int, error) {
	return 0, nil
}
func (NoopRateLimiter) CheckSignup(ctx context.Context, ip string) error         { return nil }
func (NoopRateLimiter) RecordSignupAttempt(ctx context.Context, ip string) error { return nil }
func (NoopRateLimiter) CheckPasswordResetRequest(ctx context.Context, ip, email string) error {
	return nil
}
func (NoopRateLimiter) RecordPasswordResetRequest(ctx context.Context, ip, email string) error {
	return nil
}

var _ ratelimiter.RedisLimiter = NoopRateLimiter{}

func NewDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// SeedTenant inserts a minimal active tenant row directly. TenantRepository
// is deliberately read-only (see its doc comment), so fixtures have to go
// straight through SQL rather than the repo.
func SeedTenant(t *testing.T, db *sql.DB) (id uuid.UUID, name string) {
	t.Helper()
	id = uuid.New()
	name = "test-tenant-" + id.String()[:8]
	now := time.Now()

	_, err := db.Exec(`
		INSERT INTO tenants (
			tenant_id, tenant_name, name, url, email, status,
			public_key, api_key_hash, created_at, updated_at
		) VALUES ($1, $2, $3, 'https://example.test', 'tenant@example.test',
		          'active', 'test-public-key', 'test-api-key-hash', $4, $4)`,
		id, name, name, now,
	)
	require.NoError(t, err)
	return id, name
}
