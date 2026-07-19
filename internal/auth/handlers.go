package auth

import (
	"AuthAPI/main/internal/config"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

/*
type UserStatus string

const (
provisioning
active
full
)
*/

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ClientID     string `json:"client_id"`
}

type RefreshResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresAt string `json:"refresh_expires_at"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type ResendVerificationRequest struct {
	Email string `json:"email"`
}

type RegisterVerboseResponse struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

type SignupRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

//////////////////////////////////

type UserSignupMetada struct {
	UserID   uuid.UUID `json:"user_id"`
	Email    string    `json:"email"`
	Username string    `json:"username"`
	Status   string    `json:"status"`
}

type SignupResponse struct {
	AccessToken  string           `json:"access_token"`
	RefreshToken string           `json:"refresh_token"`
	UserMetadata UserSignupMetada `json:"user_metadata"`
}

//////////////////////////////////

type SignupResponseTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	/*
		ExpiresIn        int64 `json:"expires_in"`
		RefreshExpiresIn int64 `json:"refresh_expires_in"`
	*/
}

type SignupResponseUserInfo struct {
	UserID    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"created_at"`
}

type SignupResponseRefactor struct {
	UserToken SignupResponseTokens   `json:"tokens"`
	UserInfo  SignupResponseUserInfo `json:"user"`
}

//////////////////////////////////

func ClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}

	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return xr
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func registerHandler(s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}

		if err := s.Register(r.Context(), req.Email, req.Password); err != nil {
			/* http.Error(w, err.Error(), http.StatusConflict) */
			http.Error(w, "registration failed", http.StatusConflict)
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}

// signupHandler acts as a more complex register endpoint that works with the message broker to create a user across multiple consumer APIs
// accepts (should) username
func signupHandler(s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SignupRequest

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}

		resp, err := s.SignupService(
			r.Context(),
			req.Email,
			req.Username,
			req.Password,
		)
		if err != nil {
			http.Error(w, "registration failed", http.StatusConflict)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}
}

func verifyEmailHandler(s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawToken := r.URL.Query().Get("t")
		if rawToken == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}

		if err := s.VerifyEmail(r.Context(), rawToken); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Email verified successfully, You can close this tab now"))
	}
}

func resendVerificationHandler(s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ResendVerificationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		if req.Email == "" {
			http.Error(w, "email required", http.StatusBadRequest)
			return
		}

		if err := s.ResendVerification(r.Context(), req.Email); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func loginHandler(s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		/* ip := ClientIP(r) */
		println("ping login")

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		token, refresh_token, clientID, err := s.Login(r.Context(), req.Email, req.Password)
		if err != nil {
			switch {
			case errors.Is(err, ErrEmailNotVerified):
				http.Error(w, err.Error(), http.StatusForbidden)
			case errors.Is(err, ErrInvalidCredentials):
				http.Error(w, err.Error(), http.StatusUnauthorized)
			default:
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := LoginResponse{
			AccessToken:  token,
			RefreshToken: refresh_token,
			ClientID:     clientID,
		}

		json.NewEncoder(w).Encode(resp)
	}
}

func refreshHandler(s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RefreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		if req.RefreshToken == "" {
			http.Error(w, "refresh_token required", http.StatusBadRequest)
			return
		}

		accessToken, refreshToken, expiresAt, err := s.Refresh(r.Context(), req.RefreshToken)
		if err != nil {
			http.Error(w, "invalid refresh token", http.StatusUnauthorized)
			return
		}

		json.NewEncoder(w).Encode(RefreshResponse{
			AccessToken:      accessToken,
			RefreshToken:     refreshToken,
			RefreshExpiresAt: expiresAt.UTC().Format(time.RFC3339),
		})
	}
}

func logoutHandler(s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LogoutRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		if err := s.Logout(r.Context(), req.RefreshToken); err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func revokeAllHandler(s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		userID, ok := UserIDFromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		parseID, err := uuid.Parse(userID)
		if err != nil {
			http.Error(w, "Invalid ID", http.StatusInternalServerError)
			return
		}

		if err := s.RevokeAll(r.Context(), parseID); err != nil {
			http.Error(w, "failed to revoke tokens", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func meHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value(ContextUserID).(string)
		email := r.Context().Value(ContextEmail).(string)

		json.NewEncoder(w).Encode(map[string]string{
			"user_id": userID,
			"email":   email,
		})
	}
}

func RegisterRoutes(
	app config.App,
	r chi.Router,
) {

	/* service := NewService(repo, refreshRepo, emailRepo, mailerconfig, privateKey, tokenSecret)
	 */

	service := NewService(app.UserRepo, app.RefreshRepo, app.EmailRepo, app.Mailer, app.PrivateKey, app.TokenSecret, app.OutboxRepo)

	r.Post("/register", registerHandler(service))
	r.Post("/login", loginHandler(service))
	r.Post("/refresh", refreshHandler(service))
	r.Post("/logout", logoutHandler(service))
	r.Get("/verify-email", verifyEmailHandler(service))
	r.Post("/resend-verification", resendVerificationHandler(service))
	// r.Post("/signup", signupHandler(service)) inactive for now
	/* Todo:
	- change URLs to standard
	- remeber wtf does this mean???
	*/

	r.Group(func(r chi.Router) {
		r.Use(JWTMiddleware(app.PublicKey))
		r.Get("/me", meHandler())
		r.Post("/revoke-all", revokeAllHandler(service))
	})
}
