package tests

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
	"sync"
	"testing"

	"AuthAPI/main/internal/auth"
	"AuthAPI/main/internal/auth/app"
	"AuthAPI/main/internal/auth/mail"
	"AuthAPI/main/internal/auth/refresh"
	"AuthAPI/main/internal/config"
	"AuthAPI/main/internal/outbox"
	"AuthAPI/main/internal/users"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

var (
	testDB            *sql.DB
	dockerUnavailable string
)

type e2eClient struct {
	srv *httptest.Server
	hc  *http.Client
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func uniqueEmail(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("svc-test-%s@example.com", uuid.NewString())
}

func newTestRouter(t *testing.T) (*chi.Mux, *rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()

	db := RequirePostgres(t, testDB, dockerUnavailable)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	logger := newTestLogger()

	a := app.App{ //#nosec
		UserRepo:    users.NewUserRepo("postgres", db),
		RefreshRepo: refresh.NewPostgresRefreshRepo(db),
		EmailRepo:   mail.NewEmailVerificationRepo("postgres", db),
		Mailer:      &mail.SMTPMailer{}, // zero-value: only /register touches this, async and error-ignored
		PrivateKey:  priv,
		PublicKey:   &priv.PublicKey,
		TokenSecret: "test-token-secret",
		OutboxRepo:  outbox.NewOutboxRepoAuxiliary("postgres", db),
		Logger:      logger,
	}
	/*nts: TODO: Wire this up */
	r := config.InitRouter(&config.Config{}, &priv.PublicKey, logger, func(r chi.Router) {
		auth.RegisterRoutes(a, r, db, "")
	})

	return r, priv, &priv.PublicKey
}

func newE2EClient(t *testing.T) *e2eClient {
	t.Helper()
	r, _, _ := newTestRouter(t)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return &e2eClient{srv: srv, hc: srv.Client()}
}

func (c *e2eClient) post(t *testing.T, path string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, json.NewEncoder(&buf).Encode(body))

	resp, err := c.hc.Post(c.srv.URL+path, "application/json", &buf)
	require.NoError(t, err)
	return resp
}

func (c *e2eClient) get(t *testing.T, path, bearer string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, c.srv.URL+path, nil)
	require.NoError(t, err)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.hc.Do(req)
	require.NoError(t, err)
	return resp
}

func decodeBody[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	//defer resp.Body.Close()
	defer func() {
		if err := resp.Body.Close(); err != nil {
			println(err.Error())
		}
	}()
	var out T
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// --- Full flow ----------------------------------------------

func TestE2E_FullUserJourney(t *testing.T) {
	c := newE2EClient(t)
	email := uniqueEmail(t)

	// Signup
	signupResp := c.post(t, "/signup", map[string]string{
		"email": email, "username": "e2euser", "password": "password123",
	})
	require.Equal(t, http.StatusCreated, signupResp.StatusCode)
	signup := decodeBody[auth.SignupResponseRefactor](t, signupResp)
	require.NotEmpty(t, signup.UserToken.AccessToken)

	// Login (independent session from signup's own token pair)
	loginResp := c.post(t, "/login", map[string]string{
		"email": email, "password": "password123",
	})
	require.Equal(t, http.StatusOK, loginResp.StatusCode)
	login := decodeBody[auth.LoginResponse](t, loginResp)

	// Access protected resource
	meResp := c.get(t, "/me", login.AccessToken)
	require.Equal(t, http.StatusOK, meResp.StatusCode)
	me := decodeBody[map[string]string](t, meResp)
	require.Equal(t, email, me["email"])

	// Refresh
	refreshResp := c.post(t, "/refresh", map[string]string{"refresh_token": login.RefreshToken})
	require.Equal(t, http.StatusOK, refreshResp.StatusCode)
	refreshed := decodeBody[auth.RefreshResponse](t, refreshResp)
	require.NotEqual(t, login.RefreshToken, refreshed.RefreshToken)

	// New access token from refresh also works against a protected route
	meResp2 := c.get(t, "/me", refreshed.AccessToken)
	require.Equal(t, http.StatusOK, meResp2.StatusCode)

	// Logout with the rotated token
	logoutResp := c.post(t, "/logout", map[string]string{"refresh_token": refreshed.RefreshToken})
	require.Equal(t, http.StatusNoContent, logoutResp.StatusCode)

	// Session is dead
	deadResp := c.post(t, "/refresh", map[string]string{"refresh_token": refreshed.RefreshToken})
	require.Equal(t, http.StatusUnauthorized, deadResp.StatusCode)
}

// --- Concurrency: this is the scenario unit/integration tests can't cover,
// since it depends on real concurrent HTTP round-trips racing against the
// same DB row, not sequential calls into Service. ----------------------

func TestE2E_ConcurrentRefresh_OnlyOneWinnerNoFamilyCorruption(t *testing.T) {
	c := newE2EClient(t)
	email := uniqueEmail(t)

	c.post(t, "/signup", map[string]string{
		"email": email, "username": "e2euser", "password": "password123",
	})
	loginResp := c.post(t, "/login", map[string]string{"email": email, "password": "password123"})
	login := decodeBody[auth.LoginResponse](t, loginResp)

	const attempts = 10
	var (
		wg            sync.WaitGroup
		mu            sync.Mutex
		successCount  int
		conflictCount int
	)

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := c.post(t, "/refresh", map[string]string{"refresh_token": login.RefreshToken})
			//defer resp.Body.Close()
			defer func() {
				if err := resp.Body.Close(); err != nil {
					println(err.Error())
				}
			}()

			mu.Lock()
			defer mu.Unlock()
			switch resp.StatusCode {
			case http.StatusOK:
				successCount++
			case http.StatusUnauthorized:
				conflictCount++
			default:
				t.Errorf("unexpected status %d from concurrent refresh", resp.StatusCode)
			}
		}()
	}
	wg.Wait()

	// Exactly one of the racing requests should win the rotation; the rest
	// should be rejected (either as "already rotated" or as reuse, both of
	// which surface as 401 here) rather than each minting its own valid
	// child token from the same parent.
	require.Equal(t, 1, successCount, "exactly one concurrent refresh should succeed")
	require.Equal(t, attempts-1, conflictCount)
}

// --- Availability endpoints ------------------------------------------------

func TestE2E_HealthEndpoint(t *testing.T) {
	c := newE2EClient(t)
	resp := c.get(t, "/health", "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestE2E_MetricsEndpoint_Reachable(t *testing.T) {
	c := newE2EClient(t)
	resp := c.get(t, "/metrics", "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestE2E_SwaggerEndpoint_Reachable(t *testing.T) {
	c := newE2EClient(t)
	resp := c.get(t, "/swagger/index.html", "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestE2E_RequestIDIsEchoedInResponseHeader(t *testing.T) {
	c := newE2EClient(t)
	resp := c.get(t, "/health", "")
	require.NotEmpty(t, resp.Header.Get("X-Request-ID"))
}

func TestE2E_ClientProvidedRequestIDIsRespected(t *testing.T) {
	c := newE2EClient(t)

	req, err := http.NewRequest(http.MethodGet, c.srv.URL+"/health", nil)
	require.NoError(t, err)
	req.Header.Set("X-Request-ID", "client-supplied-id-123")

	resp, err := c.hc.Do(req)
	require.NoError(t, err)
	require.Equal(t, "client-supplied-id-123", resp.Header.Get("X-Request-ID"))
}
