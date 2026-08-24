package authtests

/*
import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"os"
	"sync"
	"testing"

	"AuthAPI/main/internal/auth"
	"AuthAPI/main/internal/auth/mail"
	"AuthAPI/main/internal/auth/refresh"
	"AuthAPI/main/internal/crypto"
	"AuthAPI/main/internal/outbox"
	"AuthAPI/main/internal/tests"
	"AuthAPI/main/internal/users"

	"github.com/stretchr/testify/require"
)

// testDB/dockerUnavailable are package-level so every test in this
// package shares one Postgres testcontainer for the whole run, same
// pattern used in internal/users, internal/outbox, internal/auth/refresh.
// This package (internal/tests) hosts the SetupTestDB/RequirePostgres
// helpers themselves, so TestMain calls them unqualified rather than via
// a "tests." prefix.

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

func newFakeMailer() *fakeMailer {
	return &fakeMailer{
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

func newServiceTestSetup(t *testing.T) (*auth.Service, *sql.DB, *fakeMailer) {
	t.Helper()

	db := tests.RequirePostgres(t, testDB, dockerUnavailable)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	userRepo := users.NewUserRepo("postgres", db)
	refreshRepo := refresh.NewPostgresRefreshRepo(db)
	emailVerifyRepo := mail.NewEmailVerificationRepo("postgres", db)
	outboxRepo := outbox.NewOutboxRepo("postgres", db)
	mailer := newFakeMailer()

	// nts: TODO: wire this up

	svc := auth.NewService(
		userRepo,
		refreshRepo,
		emailVerifyRepo,
		mailer,
		priv,
		"test-token-secret",
		outboxRepo,
		db,
		"",
	)

	return svc, db, mailer
}

// --- Signup -----------------------------------------------------------

func TestService_SignupService_Success(t *testing.T) {
	svc, db, _ := newServiceTestSetup(t)
	ctx := context.Background()

	email := uniqueEmail(t)
	resp, err := svc.SignupService(ctx, email, "someuser", "password123")
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

func TestService_SignupService_DuplicateEmail(t *testing.T) {
	svc, _, _ := newServiceTestSetup(t)
	ctx := context.Background()
	email := uniqueEmail(t)

	_, err := svc.SignupService(ctx, email, "first", "password123")
	require.NoError(t, err)

	_, err = svc.SignupService(ctx, email, "second", "password456")
	require.ErrorIs(t, err, auth.ErrEmailAlreadyExists)
}

// --- Login --------------------------------------------------------------

func TestService_Login_Success(t *testing.T) {
	svc, _, _ := newServiceTestSetup(t)
	ctx := context.Background()
	email := uniqueEmail(t)

	_, err := svc.SignupService(ctx, email, "someuser", "password123")
	require.NoError(t, err)

	access, refreshToken, clientID, err := svc.Login(ctx, email, "password123")
	require.NoError(t, err)
	require.NotEmpty(t, access)
	require.NotEmpty(t, refreshToken)
	require.NotEmpty(t, clientID)
}

func TestService_Login_WrongPassword(t *testing.T) {
	svc, _, _ := newServiceTestSetup(t)
	ctx := context.Background()
	email := uniqueEmail(t)

	_, err := svc.SignupService(ctx, email, "someuser", "password123")
	require.NoError(t, err)

	_, _, _, err = svc.Login(ctx, email, "wrong-password")
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

func TestService_Login_UnknownEmail(t *testing.T) {
	svc, _, _ := newServiceTestSetup(t)
	ctx := context.Background()

	_, _, _, err := svc.Login(ctx, uniqueEmail(t), "password123")
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

// --- Refresh rotation & reuse detection ----------------------------------

func TestService_Refresh_RotatesTokenAndRevokesOld(t *testing.T) {
	svc, db, _ := newServiceTestSetup(t)
	ctx := context.Background()
	email := uniqueEmail(t)

	_, err := svc.SignupService(ctx, email, "someuser", "password123")
	require.NoError(t, err)

	_, oldRefresh, _, err := svc.Login(ctx, email, "password123")
	require.NoError(t, err)

	newAccess, newRefresh, expiresAt, err := svc.Refresh(ctx, oldRefresh)
	require.NoError(t, err)
	require.NotEmpty(t, newAccess)
	require.NotEmpty(t, newRefresh)
	require.NotEqual(t, oldRefresh, newRefresh)
	require.False(t, expiresAt.IsZero())

	var revokedAt sql.NullTime
	hash := crypto.HashToken(oldRefresh, "test-token-secret")
	require.NoError(t, db.QueryRow(
		`SELECT revoked_at FROM refresh_tokens WHERE token_hash = $1`, hash,
	).Scan(&revokedAt))
	require.True(t, revokedAt.Valid, "old refresh token should be revoked after rotation")
}

func TestService_Refresh_ReuseOfRotatedToken_RevokesEntireFamily(t *testing.T) {
	svc, db, _ := newServiceTestSetup(t)
	ctx := context.Background()
	email := uniqueEmail(t)

	_, err := svc.SignupService(ctx, email, "someuser", "password123")
	require.NoError(t, err)

	_, firstRefresh, _, err := svc.Login(ctx, email, "password123")
	require.NoError(t, err)

	// Legitimate rotation: first -> second.
	_, secondRefresh, _, err := svc.Refresh(ctx, firstRefresh)
	require.NoError(t, err)

	// Replay attack: reuse the already-rotated first token.
	_, _, _, err = svc.Refresh(ctx, firstRefresh)
	require.ErrorIs(t, err, auth.ErrRefreshReuse)

	// The entire family must be revoked, so the attacker's replay can't be worked around by continuing to use the "good" token either.
	hash := crypto.HashToken(secondRefresh, "test-token-secret")
	var revokedAt sql.NullTime
	require.NoError(t, db.QueryRow(
		`SELECT revoked_at FROM refresh_tokens WHERE token_hash = $1`, hash,
	).Scan(&revokedAt))
	require.True(t, revokedAt.Valid, "sibling token in the family should be revoked too")

	// And attempting to refresh with the "good" second token should fail (it's revoked, so this itself is treated as reuse).
	_, _, _, err = svc.Refresh(ctx, secondRefresh)
	require.Error(t, err)
}

func TestService_Refresh_InvalidToken(t *testing.T) {
	svc, _, _ := newServiceTestSetup(t)
	ctx := context.Background()

	_, _, _, err := svc.Refresh(ctx, "not-a-real-refresh-token")
	require.ErrorIs(t, err, auth.ErrInvalidToken)
}

// --- Logout & revoke-all -------------------------------------------------

func TestService_Logout_RevokesToken(t *testing.T) {
	svc, _, _ := newServiceTestSetup(t)
	ctx := context.Background()
	email := uniqueEmail(t)

	_, err := svc.SignupService(ctx, email, "someuser", "password123")
	require.NoError(t, err)

	_, refreshToken, _, err := svc.Login(ctx, email, "password123")
	require.NoError(t, err)

	require.NoError(t, svc.Logout(ctx, refreshToken))

	// Using the logged-out token again must fail.
	_, _, _, err = svc.Refresh(ctx, refreshToken)
	require.Error(t, err)
}

func TestService_RevokeAll_RevokesEverySessionForUser(t *testing.T) {
	svc, db, _ := newServiceTestSetup(t)
	ctx := context.Background()
	email := uniqueEmail(t)

	_, err := svc.SignupService(ctx, email, "someuser", "password123")
	require.NoError(t, err)

	// Two independent sessions (two logins => two token families).
	_, refreshA, _, err := svc.Login(ctx, email, "password123")
	require.NoError(t, err)
	_, refreshB, _, err := svc.Login(ctx, email, "password123")
	require.NoError(t, err)

	userID := userIDByEmail(t, db, email)

	require.NoError(t, svc.RevokeAll(ctx, userID))

	_, _, _, errA := svc.Refresh(ctx, refreshA)
	require.Error(t, errA)

	_, _, _, errB := svc.Refresh(ctx, refreshB)
	require.Error(t, errB)
}

// --- Email verification ---------------------------------------------------

func TestService_VerifyEmail_InvalidToken(t *testing.T) {
	svc, _, _ := newServiceTestSetup(t)
	ctx := context.Background()

	err := svc.VerifyEmail(ctx, "not-a-real-token")
	require.ErrorIs(t, err, auth.ErrInvalidVerificationToken)
}

func TestService_ResendVerification_UnknownEmailDoesNotError(t *testing.T) {
	svc, _, _ := newServiceTestSetup(t)
	ctx := context.Background()

	err := svc.ResendVerification(ctx, uniqueEmail(t))
	require.NoError(t, err)
}
*/
