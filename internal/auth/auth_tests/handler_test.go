package authtests

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
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
	"github.com/stretchr/testify/require"
)

// newHandlerTestServer builds a real router against the shared test
// Postgres and returns a client plus the seeded tenant's header value,
// since every /auth route except /me and /revoke-all requires X-Tenant.
func newHandlerTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	db := tests.RequirePostgres(t, testDB, dockerUnavailable)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub := &priv.PublicKey
	logger := tests.NewDiscardLogger()
	tenantRepo := tenants.NewTenantRepo("postgres", db)
	_, tenantName := tests.SeedTenant(t, db)

	a := app.App{ // #nosec G101
		UserRepo:     users.NewUserRepo("postgres", db),
		RefreshRepo:  refresh.NewPostgresRefreshRepo(db),
		EmailRepo:    mail.NewEmailVerificationRepo("postgres", db),
		Mailer:       &mail.SMTPMailer{},
		PrivateKey:   priv,
		PublicKey:    pub,
		TokenSecret:  "test-token-secret",
		OutboxRepo:   outbox.NewOutboxRepo("postgres", db),
		TenantRepo:   tenantRepo,
		Logger:       logger,
		RedisLimiter: tests.NoopRateLimiter{},
	}

	r := config.InitRouter(&config.Config{}, pub, logger, tenantRepo, func(r chi.Router) {
		auth.RegisterRoutes(a, r, db, "")
	})

	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv, tenantName
}

func postJSON(t *testing.T, srv *httptest.Server, tenant, path string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, json.NewEncoder(&buf).Encode(body))

	req, err := http.NewRequest(http.MethodPost, srv.URL+path, &buf)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if tenant != "" {
		req.Header.Set(auth.TenantHeader, tenant)
	}
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	return resp
}

func getWithAuth(t *testing.T, srv *httptest.Server, path, bearer string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	require.NoError(t, err)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	return resp
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()

	var out T
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// --- Signup ---------------------------------------------------------------

func TestHandler_Signup_Success(t *testing.T) {
	srv, tenant := newHandlerTestServer(t)
	resp := postJSON(t, srv, tenant, "/auth/signup", map[string]string{
		"email": uniqueEmail(t), "username": "handleruser", "password": "password123",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
}

func TestHandler_Signup_InvalidEmail(t *testing.T) {
	srv, tenant := newHandlerTestServer(t)
	resp := postJSON(t, srv, tenant, "/auth/signup", map[string]string{
		"email": "not-an-email", "username": "u", "password": "password123",
	})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandler_Signup_ShortPassword(t *testing.T) {
	srv, tenant := newHandlerTestServer(t)
	resp := postJSON(t, srv, tenant, "/auth/signup", map[string]string{
		"email": uniqueEmail(t), "username": "u", "password": "ab",
	})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandler_Signup_DuplicateEmail(t *testing.T) {
	srv, tenant := newHandlerTestServer(t)
	email := uniqueEmail(t)
	body := map[string]string{"email": email, "username": "u", "password": "password123"}

	require.Equal(t, http.StatusCreated, postJSON(t, srv, tenant, "/auth/signup", body).StatusCode)
	dup := postJSON(t, srv, tenant, "/auth/signup", body)
	require.NotEqual(t, http.StatusCreated, dup.StatusCode)
}

func TestHandler_Signup_MalformedJSON(t *testing.T) {
	srv, tenant := newHandlerTestServer(t)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/auth/signup", bytes.NewBufferString("{not json"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(auth.TenantHeader, tenant)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandler_Signup_UnknownFieldsRejected(t *testing.T) {
	srv, tenant := newHandlerTestServer(t)
	resp := postJSON(t, srv, tenant, "/auth/signup", map[string]string{
		"email": uniqueEmail(t), "username": "u", "password": "password123", "is_admin": "true",
	})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// --- Login ------------------------------------------------------------

func TestHandler_Login_Success(t *testing.T) {
	srv, tenant := newHandlerTestServer(t)
	email := uniqueEmail(t)
	postJSON(t, srv, tenant, "/auth/signup", map[string]string{
		"email": email, "username": "u", "password": "password123",
	})

	resp := postJSON(t, srv, tenant, "/auth/login", map[string]string{
		"email": email, "password": "password123",
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	login := decode[auth.LoginResponse](t, resp)
	require.NotEmpty(t, login.AccessToken)
}

func TestHandler_Login_WrongPassword(t *testing.T) {
	srv, tenant := newHandlerTestServer(t)
	email := uniqueEmail(t)
	postJSON(t, srv, tenant, "/auth/signup", map[string]string{
		"email": email, "username": "u", "password": "password123",
	})

	resp := postJSON(t, srv, tenant, "/auth/login", map[string]string{
		"email": email, "password": "wrong12345",
	})
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHandler_Login_UnknownFieldsRejected(t *testing.T) {
	srv, tenant := newHandlerTestServer(t)
	resp := postJSON(t, srv, tenant, "/auth/login", map[string]string{
		"email": uniqueEmail(t), "password": "password123", "remember_me": "true",
	})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// --- Refresh ------------------------------------------------------------

func loginAndGetTokens(t *testing.T, srv *httptest.Server, tenant string) auth.LoginResponse {
	t.Helper()
	email := uniqueEmail(t)
	postJSON(t, srv, tenant, "/auth/signup", map[string]string{
		"email": email, "username": "u", "password": "password123",
	})
	resp := postJSON(t, srv, tenant, "/auth/login", map[string]string{
		"email": email, "password": "password123",
	})
	return decode[auth.LoginResponse](t, resp)
}

func TestHandler_Refresh_Success(t *testing.T) {
	srv, tenant := newHandlerTestServer(t)
	login := loginAndGetTokens(t, srv, tenant)

	resp := postJSON(t, srv, tenant, "/auth/refresh", map[string]string{"refresh_token": login.RefreshToken})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	refreshed := decode[auth.RefreshResponse](t, resp)
	require.NotEqual(t, login.RefreshToken, refreshed.RefreshToken)
}

func TestHandler_Refresh_ReuseDetected(t *testing.T) {
	srv, tenant := newHandlerTestServer(t)
	login := loginAndGetTokens(t, srv, tenant)

	postJSON(t, srv, tenant, "/auth/refresh", map[string]string{"refresh_token": login.RefreshToken})
	reuse := postJSON(t, srv, tenant, "/auth/refresh", map[string]string{"refresh_token": login.RefreshToken})
	require.Equal(t, http.StatusUnauthorized, reuse.StatusCode)
}

func TestHandler_Refresh_MissingToken(t *testing.T) {
	srv, tenant := newHandlerTestServer(t)
	resp := postJSON(t, srv, tenant, "/auth/refresh", map[string]string{})
	require.NotEqual(t, http.StatusOK, resp.StatusCode)
}

// --- Logout -------------------------------------------------------------

func TestHandler_Logout_Success(t *testing.T) {
	srv, tenant := newHandlerTestServer(t)
	login := loginAndGetTokens(t, srv, tenant)

	resp := postJSON(t, srv, tenant, "/auth/logout", map[string]string{"refresh_token": login.RefreshToken})
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
}

// --- Me / RevokeAll (JWT-protected, no X-Tenant needed today) -----------

func TestHandler_Me_ValidToken_ReturnsUserInfo(t *testing.T) {
	srv, tenant := newHandlerTestServer(t)
	login := loginAndGetTokens(t, srv, tenant)

	resp := getWithAuth(t, srv, "/auth/me", login.AccessToken)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHandler_Me_NoToken_Unauthorized(t *testing.T) {
	srv, _ := newHandlerTestServer(t)
	resp := getWithAuth(t, srv, "/auth/me", "")
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHandler_Me_InvalidToken_Unauthorized(t *testing.T) {
	srv, _ := newHandlerTestServer(t)
	resp := getWithAuth(t, srv, "/auth/me", "not-a-real-token")
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHandler_RevokeAll_NoToken_Unauthorized(t *testing.T) {
	srv, _ := newHandlerTestServer(t)
	resp, err := srv.Client().Post(srv.URL+"/auth/revoke-all", "application/json", nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// --- Health ---------------------------------------------------------------

func TestHandler_Health_ReturnsOK(t *testing.T) {
	srv, _ := newHandlerTestServer(t)
	resp, err := srv.Client().Get(srv.URL + "/auth/health")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}
