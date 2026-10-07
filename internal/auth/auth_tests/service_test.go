package authtests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"AuthAPI/main/internal/auth"
	"AuthAPI/main/internal/auth/app"
	"AuthAPI/main/internal/auth/mail"
	"AuthAPI/main/internal/auth/ratelimiter"
	"AuthAPI/main/internal/auth/refresh"
	"AuthAPI/main/internal/auth/tenants"
	"AuthAPI/main/internal/models"
	"AuthAPI/main/internal/outbox"
	"AuthAPI/main/internal/tests"
	"AuthAPI/main/internal/users"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// testDB/dockerUnavailable are package-level so every test in this package
// shares one Postgres testcontainer for the whole run, matching the pattern
// in internal/users, internal/outbox, internal/auth/refresh.
var (
	testDB            *sql.DB
	dockerUnavailable string
)

func TestMain(m *testing.M) {
	var teardown func()
	testDB, dockerUnavailable, teardown = tests.SetupTestDB()
	defer teardown()
	os.Exit(m.Run())
}

type fakeMailer struct {
	mu   sync.Mutex //nolint:unused
	sent chan struct {
		to    string
		token string
	}
}

func NewFakeMailer() fakeMailer {
	return fakeMailer{
		sent: make(chan struct {
			to    string
			token string
		}, 8),
	}
}

func (f *fakeMailer) SendVerificationEmail(to string, token string) error {
	f.sent <- struct {
		to    string
		token string
	}{to, token}
	return nil
}

var _ mail.Mailer = (*fakeMailer)(nil)

// newServiceTestSetup wires a Service against the shared test Postgres,
// seeds a tenant, and returns a context that already carries it — every
// Service method that calls auth.TenantFromContext(ctx) is satisfied by
// just passing this ctx straight through.
func newServiceTestSetup(t *testing.T) (svc *auth.Service, db *sql.DB, mailer *fakeMailer, ctx context.Context, tenant *models.Tenant) {
	t.Helper()

	db = tests.RequirePostgres(t, testDB, dockerUnavailable)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tenantRepo := tenants.NewTenantRepo("postgres", db)
	_, tenantName := tests.SeedTenant(t, db)
	tenant, err = tenantRepo.FindByTenantName(context.Background(), tenantName)
	require.NoError(t, err)

	userRepo := users.NewUserRepo("postgres", db)
	refreshRepo := refresh.NewPostgresRefreshRepo(db)
	emailVerifyRepo := mail.NewEmailVerificationRepo("postgres", db)
	outboxRepo := outbox.NewOutboxRepo("postgres", db)
	temp := NewFakeMailer()
	mailer = &temp

	app := app.App{
		UserRepo:     userRepo,
		RefreshRepo:  refreshRepo,
		EmailRepo:    emailVerifyRepo,
		Mailer:       &mail.SMTPMailer{},
		PrivateKey:   priv,
		PublicKey:    &priv.PublicKey,
		TokenSecret:  "test",
		OutboxRepo:   outboxRepo,
		TenantRepo:   tenantRepo,
		Logger:       slog.Default(),
		Redisclient:  &redis.Client{},
		RedisLimiter: &ratelimiter.RedisClient{},
	}

	svc = auth.NewService(
		db,
		"",
		app,
	)

	ctx = context.WithValue(context.Background(), auth.ContextTenant, tenant)
	return svc, db, mailer, ctx, tenant
}

func uniqueEmail(t *testing.T) string {
	t.Helper()
	return "svc-test-" + uuid.NewString() + "@example.com"
}

// --- Signup -----------------------------------------------------------

func TestService_SignupService_Success(t *testing.T) {
	svc, db, _, ctx, tenant := newServiceTestSetup(t)

	email := uniqueEmail(t)
	resp, err := svc.SignupService(ctx, email, "someuser", "password123", tenant.ID)
	require.NoError(t, err)
	require.NotEmpty(t, resp.UserToken.AccessToken)
	require.NotEmpty(t, resp.UserToken.RefreshToken)
	require.Equal(t, email, resp.UserInfo.Email)
	require.False(t, resp.UserInfo.Verified)

	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM users WHERE email = $1`, email).Scan(&count))
	require.Equal(t, 1, count)

	var outboxCount int
	require.NoError(t, db.QueryRow(
		`SELECT COUNT(*) FROM outbox_events WHERE event_type = 'user.created'`,
	).Scan(&outboxCount))
	require.GreaterOrEqual(t, outboxCount, 1)
}

func TestService_SignupService_DuplicateEmail_Fails(t *testing.T) {
	svc, _, _, ctx, tenant := newServiceTestSetup(t)
	email := uniqueEmail(t)

	_, err := svc.SignupService(ctx, email, "user1", "password123", tenant.ID)
	require.NoError(t, err)

	_, err = svc.SignupService(ctx, email, "user2", "password123", tenant.ID)
	require.Error(t, err)
}

func TestService_SignupService_NoTenantInContext_Fails(t *testing.T) {
	svc, _, _, _, tenant := newServiceTestSetup(t)

	_, err := svc.SignupService(context.Background(), uniqueEmail(t), "someuser", "password123", tenant.ID)
	require.Error(t, err, "SignupService reads the tenant from context separately from the uuid param; a bare context should fail, not silently use the param")
}

// --- Login --------------------------------------------------------------

func TestService_Login_Success(t *testing.T) {
	svc, _, _, ctx, tenant := newServiceTestSetup(t)
	email := uniqueEmail(t)

	_, err := svc.SignupService(ctx, email, "loginuser", "password123", tenant.ID)
	require.NoError(t, err)

	access, refreshToken, clientID, err := svc.Login(ctx, email, "password123", "127.0.0.1")
	require.NoError(t, err)
	require.NotEmpty(t, access)
	require.NotEmpty(t, refreshToken)
	require.NotEmpty(t, clientID)
}

func TestService_Login_WrongPassword_Fails(t *testing.T) {
	svc, _, _, ctx, tenant := newServiceTestSetup(t)
	email := uniqueEmail(t)

	_, err := svc.SignupService(ctx, email, "loginuser", "password123", tenant.ID)
	require.NoError(t, err)

	_, _, _, err = svc.Login(ctx, email, "wrong-password", "127.0.0.1")
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

func TestService_Login_UnknownEmail_FailsSameAsWrongPassword(t *testing.T) {
	svc, _, _, ctx, _ := newServiceTestSetup(t)

	_, _, _, err := svc.Login(ctx, uniqueEmail(t), "whatever", "127.0.0.1")
	require.ErrorIs(t, err, auth.ErrInvalidCredentials,
		"unknown account and wrong password must be indistinguishable to the caller")
}

// --- Refresh --------------------------------------------------------------

func TestService_Refresh_RotatesToken(t *testing.T) {
	svc, _, _, ctx, tenant := newServiceTestSetup(t)
	email := uniqueEmail(t)

	_, err := svc.SignupService(ctx, email, "refreshuser", "password123", tenant.ID)
	require.NoError(t, err)
	_, refreshToken, _, err := svc.Login(ctx, email, "password123", "127.0.0.1")
	require.NoError(t, err)

	newAccess, newRefresh, expiresAt, err := svc.Refresh(ctx, refreshToken)
	require.NoError(t, err)
	require.NotEmpty(t, newAccess)
	require.NotEqual(t, refreshToken, newRefresh)
	require.True(t, expiresAt.After(time.Now()))
}

func TestService_Refresh_ReuseDetected_RevokesFamily(t *testing.T) {
	svc, _, _, ctx, tenant := newServiceTestSetup(t)
	email := uniqueEmail(t)

	_, err := svc.SignupService(ctx, email, "reuseuser", "password123", tenant.ID)
	require.NoError(t, err)
	_, refreshToken, _, err := svc.Login(ctx, email, "password123", "127.0.0.1")
	require.NoError(t, err)

	_, rotated, _, err := svc.Refresh(ctx, refreshToken)
	require.NoError(t, err)

	// Reusing the already-rotated (now stale) token must fail...
	_, _, _, err = svc.Refresh(ctx, refreshToken)
	require.Error(t, err)

	// ...and must have burned the whole family: even the legitimately
	// rotated child is now dead.
	_, _, _, err = svc.Refresh(ctx, rotated)
	require.Error(t, err, "reuse detection should revoke the entire family, not just the reused token")
}

// --- Logout / RevokeAll --------------------------------------------------

func TestService_Logout_InvalidatesRefreshToken(t *testing.T) {
	svc, _, _, ctx, tenant := newServiceTestSetup(t)
	email := uniqueEmail(t)

	_, err := svc.SignupService(ctx, email, "logoutuser", "password123", tenant.ID)
	require.NoError(t, err)
	_, refreshToken, _, err := svc.Login(ctx, email, "password123", "127.0.0.1")
	require.NoError(t, err)

	require.NoError(t, svc.Logout(ctx, refreshToken))

	_, _, _, err = svc.Refresh(ctx, refreshToken)
	require.Error(t, err)
}

// --- Password reset -------------------------------------------------------

func TestService_RequestResetPassword_UnknownEmail_StillReturnsNil(t *testing.T) {
	svc, _, _, ctx, _ := newServiceTestSetup(t)

	err := svc.RequestResetPassword(ctx, uniqueEmail(t), "127.0.0.1")
	require.NoError(t, err, "must not leak account existence through an error")
}

func TestService_RequestResetPassword_KnownEmail_CreatesResetToken(t *testing.T) {
	svc, db, _, ctx, tenant := newServiceTestSetup(t)
	email := uniqueEmail(t)

	_, err := svc.SignupService(ctx, email, "resetuser", "password123", tenant.ID)
	require.NoError(t, err)

	require.NoError(t, svc.RequestResetPassword(ctx, email, "127.0.0.1"))

	var count int
	require.NoError(t, db.QueryRow(
		`SELECT COUNT(*) FROM password_reset_tokens prt
     JOIN users u ON u.user_id = prt.user_id
     WHERE u.email = $1`, email,
	).Scan(&count))
	require.GreaterOrEqual(t, count, 1)
}
