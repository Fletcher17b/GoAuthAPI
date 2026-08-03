package auth

import (
	"AuthAPI/main/internal/auth/app"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	_ "AuthAPI/main/docs"

	httpSwagger "github.com/swaggo/http-swagger"
)

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

type ErrorResponse struct {
	Error string `json:"error"`
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

type UserInfo struct {
	UserID    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"created_at"`
}

type SignupResponseRefactor struct {
	UserToken SignupResponseTokens `json:"tokens"`
	UserInfo  UserInfo             `json:"user"`
}

//////////////////////////////////

func writeJSON(
	w http.ResponseWriter,
	status int,
	body any,
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(body)
}

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

// registerHandler godoc
// @Summary      Register a new user
// @Description  Creates a new user account using email and password.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body object{email=string,password=string} true "Registration request"
// @Success      201
// @Failure      400 {object} ErrorResponse
// @Failure      409 {object} ErrorResponse
// @Router       /register [post]
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
			respondJSONError(w, err)
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}

// signupHandler godoc
// @Summary      Sign up a new user
// @Description  signupHandler acts as a more complex register endpoint that works with the message broker to create a user across multiple consumer APIs, accepts (should) username
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body SignupRequest true "Signup request"
// @Success      201 {object} SignupResponseRefactor
// @Failure      400 {object} ErrorResponse
// @Failure      409 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Router       /signup [post]
func signupHandler(s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SignupRequest

		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		if err := decoder.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "invalid request body",
			})
			return
		}

		if err := validateEmail(req.Email); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: err.Error(),
			})
			return
		}

		if err := validatePassword(req.Password); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: err.Error(),
			})
			return
		}

		resp, err := s.SignupService(
			r.Context(),
			req.Email,
			req.Username,
			req.Password,
		)
		if err != nil {
			respondJSONError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, resp)
	}
}

// verifyEmailHandler godoc
// @Summary      Verify email address
// @Description  Verifies a user's email using the verification token.
// @Tags         auth
// @Produce      json
// @Param token query string true "Verification token"
// @Success      200
// @Failure      400 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /verify/{token} [get]
func verifyEmailHandler(logger *slog.Logger, s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawToken := r.URL.Query().Get("t")
		if rawToken == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}

		if err := s.VerifyEmail(r.Context(), rawToken); err != nil {
			respondTextError(w, err)
			return
		}

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("Email verified successfully, You can close this tab now")); err != nil {
			logger.Error("Failire in Writing response in verifyEmailHandler")
			return
		}
	}
}

// resendVerificationHandler godoc
// @Summary      Resend verification email
// @Description  Sends a new email verification link to the user.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body ResendVerificationRequest true "Resend verification request"
// @Success      200
// @Failure      400 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /verify/resend [post]
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
			respondTextError(w, err)
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

		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		if err := decoder.Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		if err := validateEmail(req.Email); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: err.Error(),
			})
			return
		}

		if err := validatePassword(req.Password); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: err.Error(),
			})
			return
		}

		token, refresh_token, clientID, err := s.Login(r.Context(), req.Email, req.Password)
		if err != nil {
			respondJSONError(w, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := LoginResponse{
			AccessToken:  token,         // #nosec G117
			RefreshToken: refresh_token, // #nosec G117
			ClientID:     clientID,
		}

		if err := json.NewEncoder(w).Encode(resp); err != nil { // #nosec G117
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// refreshHandler godoc
// @Summary      Refresh access token
// @Description  Exchanges a valid refresh token for a new access token.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body RefreshRequest true "Refresh token"
// @Success      200 {object} RefreshResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Router       /refresh [post]
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
			respondJSONError(w, err)
			return
		}

		errr := json.NewEncoder(w).Encode(RefreshResponse{
			AccessToken:      accessToken,  // #nosec G117
			RefreshToken:     refreshToken, // #nosec G117
			RefreshExpiresAt: expiresAt.UTC().Format(time.RFC3339),
		})

		if errr != nil {
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}
	}
}

// logoutHandler godoc
// @Summary      Log out a user
// @Description  Revokes the provided refresh token.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body LogoutRequest true "Logout request"
// @Success      204
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Router       /logout [post]
func logoutHandler(s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LogoutRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		if err := s.Logout(r.Context(), req.RefreshToken); err != nil {
			respondJSONError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// revokeAllHandler godoc
// @Summary      Revoke all sessions
// @Description  Revokes all active refresh tokens for the authenticated user.
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Success      204
// @Failure      401 {object} ErrorResponse
// @Router       /logout/all [post]
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
			respondJSONError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// meHandler godoc
// @Summary      Get current user
// @Description  Returns information about the authenticated user. Internal use
// @Tags         users, internal
// @Produce      json
// @Security     BearerAuth
// @Success      200 {object} UserInfo
// @Failure      401 {object} ErrorResponse
// @Router       /me [get]
func meHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value(ContextUserID).(string)
		email := r.Context().Value(ContextEmail).(string)

		err := json.NewEncoder(w).Encode(map[string]string{
			"user_id": userID,
			"email":   email,
		})

		if err != nil {
			return
		}

	}
}

func healthhander(logger *slog.Logger, db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if err := db.PingContext(r.Context()); err != nil {

			logger.Error(
				"",
				"Health Check Failed",
				err.Error(),
			)

			w.WriteHeader(http.StatusServiceUnavailable)

			err := json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
			})

			if err != nil {
				logger.Error("Error in health check")
				return
			}

			return
		}

		logger.Debug("Alles gut with health Check")
		err := json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
		})
		if err != nil {
			logger.Error("Error in health check")
			return
		}

		// nts TODO: link the rest of the services when implemented

	}
}

func RegisterRoutes(
	app app.App,
	r chi.Router,
	db *sql.DB,
) {

	service := NewService(app.UserRepo, app.RefreshRepo, app.EmailRepo, app.Mailer, app.PrivateKey, app.TokenSecret, app.OutboxRepo, db)

	r.Post("/register", registerHandler(service))
	r.Post("/login", loginHandler(service))
	r.Post("/refresh", refreshHandler(service))
	r.Post("/logout", logoutHandler(service))
	r.Get("/verify-email", verifyEmailHandler(app.Logger, service))
	r.Post("/resend-verification", resendVerificationHandler(service))
	r.Post("/signup", signupHandler(service))
	r.Get("/health", healthhander(app.Logger, db))
	r.Get("/swagger/*", httpSwagger.WrapHandler)
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
