package authtests

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"AuthAPI/main/internal/auth"
	"AuthAPI/main/internal/auth/app"
	"AuthAPI/main/internal/auth/mail"
	"AuthAPI/main/internal/auth/refresh"
	"AuthAPI/main/internal/auth/tenants"
	"AuthAPI/main/internal/config"
	"AuthAPI/main/internal/outbox"
	"AuthAPI/main/internal/tests"
	"AuthAPI/main/internal/users"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

var (
	testDB            *sql.DB
	dockerUnavailable string
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func uniqueEmail(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("svc-test-%s@example.com", uuid.NewString())
}

func userIDByEmail(t *testing.T, db *sql.DB, email string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	require.NoError(t, db.QueryRow(`SELECT user_id FROM users WHERE email = $1`, email).Scan(&id))
	return id
}

func newTestRouter(t *testing.T) (*chi.Mux, *rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()

	db := tests.RequirePostgres(t, testDB, dockerUnavailable)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	logger := newTestLogger()

	a := app.App{ // #nosec
		UserRepo:    users.NewUserRepo("postgres", db),
		RefreshRepo: refresh.NewPostgresRefreshRepo(db),
		EmailRepo:   mail.NewEmailVerificationRepo("postgres", db),
		Mailer:      &mail.SMTPMailer{}, // zero-value: only /register touches this, async and error-ignored
		PrivateKey:  priv,
		PublicKey:   &priv.PublicKey,
		TokenSecret: "test-token-secret",
		OutboxRepo:  outbox.NewOutboxRepo("postgres", db),
		Logger:      logger,
	}

	/* nts TODO: wire this correctly */
	r := config.InitRouter(&config.Config{}, &priv.PublicKey, logger, tenants.NewTenantRepo("postgres", db), func(r chi.Router) {
		auth.RegisterRoutes(a, r, db, "")
	})

	return r, priv, &priv.PublicKey
}

func doJSON(t *testing.T, r http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}

	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func decodeJSON[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	return out
}

// --- /signup --------------------------------------------------------------

func TestHandler_Signup_Success(t *testing.T) {
	r, _, _ := newTestRouter(t)

	rec := doJSON(t, r, http.MethodPost, "/signup", map[string]string{
		"email":    uniqueEmail(t),
		"username": "someuser",
		"password": "password123",
	})

	require.Equal(t, http.StatusCreated, rec.Code)

	resp := decodeJSON[auth.SignupResponseRefactor](t, rec)
	require.NotEmpty(t, resp.UserToken.AccessToken)
	require.NotEmpty(t, resp.UserToken.RefreshToken)
	require.Equal(t, "someuser", resp.UserInfo.Username)
}

func TestHandler_Signup_InvalidEmail(t *testing.T) {
	r, _, _ := newTestRouter(t)

	rec := doJSON(t, r, http.MethodPost, "/signup", map[string]string{
		"email":    "not-an-email",
		"username": "someuser",
		"password": "password123",
	})

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_Signup_ShortPassword(t *testing.T) {
	r, _, _ := newTestRouter(t)

	rec := doJSON(t, r, http.MethodPost, "/signup", map[string]string{
		"email":    uniqueEmail(t),
		"username": "someuser",
		"password": "ab",
	})

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_Signup_DuplicateEmail(t *testing.T) {
	r, _, _ := newTestRouter(t)
	email := uniqueEmail(t)

	first := doJSON(t, r, http.MethodPost, "/signup", map[string]string{
		"email": email, "username": "first", "password": "password123",
	})
	require.Equal(t, http.StatusCreated, first.Code)

	second := doJSON(t, r, http.MethodPost, "/signup", map[string]string{
		"email": email, "username": "second", "password": "password456",
	})
	require.Equal(t, http.StatusConflict, second.Code)
}

func TestHandler_Signup_MalformedJSON(t *testing.T) {
	r, _, _ := newTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/signup", bytes.NewBufferString(`{"email": `))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_Signup_UnknownFieldsRejected(t *testing.T) {
	// signupHandler uses DisallowUnknownFields, unlike registerHandler.
	r, _, _ := newTestRouter(t)

	rec := doJSON(t, r, http.MethodPost, "/signup", map[string]any{
		"email":    uniqueEmail(t),
		"username": "someuser",
		"password": "password123",
		"is_admin": true, // unexpected field
	})

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// --- /login -----------------------------------------------------------

func TestHandler_Login_Success(t *testing.T) {
	r, _, _ := newTestRouter(t)
	email := uniqueEmail(t)

	signup := doJSON(t, r, http.MethodPost, "/signup", map[string]string{
		"email": email, "username": "someuser", "password": "password123",
	})
	require.Equal(t, http.StatusCreated, signup.Code)

	rec := doJSON(t, r, http.MethodPost, "/login", map[string]string{
		"email": email, "password": "password123",
	})
	require.Equal(t, http.StatusOK, rec.Code)

	resp := decodeJSON[auth.LoginResponse](t, rec)
	require.NotEmpty(t, resp.AccessToken)
	require.NotEmpty(t, resp.RefreshToken)
	require.NotEmpty(t, resp.ClientID)
}

func TestHandler_Login_WrongPassword(t *testing.T) {
	r, _, _ := newTestRouter(t)
	email := uniqueEmail(t)

	doJSON(t, r, http.MethodPost, "/signup", map[string]string{
		"email": email, "username": "someuser", "password": "password123",
	})

	rec := doJSON(t, r, http.MethodPost, "/login", map[string]string{
		"email": email, "password": "wrong",
	})
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandler_Login_UnknownFieldsRejected(t *testing.T) {
	r, _, _ := newTestRouter(t)

	rec := doJSON(t, r, http.MethodPost, "/login", map[string]any{
		"email": uniqueEmail(t), "password": "password123", "remember_me": true,
	})
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// --- /refresh -----------------------------------------------------------

func TestHandler_Refresh_Success(t *testing.T) {
	r, _, _ := newTestRouter(t)
	email := uniqueEmail(t)

	doJSON(t, r, http.MethodPost, "/signup", map[string]string{
		"email": email, "username": "someuser", "password": "password123",
	})
	loginRec := doJSON(t, r, http.MethodPost, "/login", map[string]string{
		"email": email, "password": "password123",
	})
	login := decodeJSON[auth.LoginResponse](t, loginRec)

	rec := doJSON(t, r, http.MethodPost, "/refresh", map[string]string{
		"refresh_token": login.RefreshToken,
	})
	require.Equal(t, http.StatusOK, rec.Code)

	resp := decodeJSON[auth.RefreshResponse](t, rec)
	require.NotEmpty(t, resp.AccessToken)
	require.NotEmpty(t, resp.RefreshToken)
	require.NotEqual(t, login.RefreshToken, resp.RefreshToken)
}

func TestHandler_Refresh_ReuseDetected(t *testing.T) {
	r, _, _ := newTestRouter(t)
	email := uniqueEmail(t)

	doJSON(t, r, http.MethodPost, "/signup", map[string]string{
		"email": email, "username": "someuser", "password": "password123",
	})
	loginRec := doJSON(t, r, http.MethodPost, "/login", map[string]string{
		"email": email, "password": "password123",
	})
	login := decodeJSON[auth.LoginResponse](t, loginRec)

	first := doJSON(t, r, http.MethodPost, "/refresh", map[string]string{"refresh_token": login.RefreshToken})
	require.Equal(t, http.StatusOK, first.Code)

	// Replaying the original (now-rotated) token must be rejected.
	second := doJSON(t, r, http.MethodPost, "/refresh", map[string]string{"refresh_token": login.RefreshToken})
	require.Equal(t, http.StatusUnauthorized, second.Code)
}

func TestHandler_Refresh_MissingToken(t *testing.T) {
	r, _, _ := newTestRouter(t)

	rec := doJSON(t, r, http.MethodPost, "/refresh", map[string]string{"refresh_token": ""})
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// --- /logout -----------------------------------------------------------

func TestHandler_Logout_Success(t *testing.T) {
	r, _, _ := newTestRouter(t)
	email := uniqueEmail(t)

	doJSON(t, r, http.MethodPost, "/signup", map[string]string{
		"email": email, "username": "someuser", "password": "password123",
	})
	loginRec := doJSON(t, r, http.MethodPost, "/login", map[string]string{
		"email": email, "password": "password123",
	})
	login := decodeJSON[auth.LoginResponse](t, loginRec)

	rec := doJSON(t, r, http.MethodPost, "/logout", map[string]string{"refresh_token": login.RefreshToken})
	require.Equal(t, http.StatusNoContent, rec.Code)

	// The same token must no longer work for refreshing.
	refreshRec := doJSON(t, r, http.MethodPost, "/refresh", map[string]string{"refresh_token": login.RefreshToken})
	require.Equal(t, http.StatusUnauthorized, refreshRec.Code)
}

// --- /me and /revoke-all (JWT-protected) ---------------------------------

func doAuthed(t *testing.T, r http.Handler, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestHandler_Me_ValidToken_ReturnsUserInfo(t *testing.T) {
	r, priv, _ := newTestRouter(t)

	userID := uuid.New()
	token, err := auth.GenerateAccessToken(userID, "user@example.com", priv)
	require.NoError(t, err)

	rec := doAuthed(t, r, http.MethodGet, "/me", token)
	require.Equal(t, http.StatusOK, rec.Code)

	var body map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.Equal(t, userID.String(), body["user_id"])
	require.Equal(t, "user@example.com", body["email"])
}

func TestHandler_Me_NoToken_Unauthorized(t *testing.T) {
	r, _, _ := newTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandler_Me_InvalidToken_Unauthorized(t *testing.T) {
	r, _, _ := newTestRouter(t)

	rec := doAuthed(t, r, http.MethodGet, "/me", "not-a-real-token")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandler_Me_TokenSignedWithWrongKey_Unauthorized(t *testing.T) {
	r, _, _ := newTestRouter(t)

	otherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token, err := auth.GenerateAccessToken(uuid.New(), "user@example.com", otherPriv)
	require.NoError(t, err)

	rec := doAuthed(t, r, http.MethodGet, "/me", token)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandler_RevokeAll_ValidToken_RevokesSessions(t *testing.T) {
	r, priv, _ := newTestRouter(t)
	email := uniqueEmail(t)

	doJSON(t, r, http.MethodPost, "/signup", map[string]string{
		"email": email, "username": "someuser", "password": "password123",
	})
	loginRec := doJSON(t, r, http.MethodPost, "/login", map[string]string{
		"email": email, "password": "password123",
	})
	login := decodeJSON[auth.LoginResponse](t, loginRec)

	// Look up the real user ID to mint a token for revoke-all (the login
	// response intentionally doesn't include it, so we ask the DB).
	db := tests.RequirePostgres(t, testDB, dockerUnavailable)
	userID := userIDByEmail(t, db, email)

	token, err := auth.GenerateAccessToken(userID, email, priv)
	require.NoError(t, err)

	rec := doAuthed(t, r, http.MethodPost, "/revoke-all", token)
	require.Equal(t, http.StatusNoContent, rec.Code)

	refreshRec := doJSON(t, r, http.MethodPost, "/refresh", map[string]string{"refresh_token": login.RefreshToken})
	require.Equal(t, http.StatusUnauthorized, refreshRec.Code)
}

func TestHandler_RevokeAll_NoToken_Unauthorized(t *testing.T) {
	r, _, _ := newTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/revoke-all", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

// --- /health -----------------------------------------------------------

func TestHandler_Health_ReturnsOK(t *testing.T) {
	r, _, _ := newTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
}
