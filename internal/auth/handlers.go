package auth

import (
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	auth "AuthAPI/main/internal/auth/refresh"
	"AuthAPI/main/internal/users"
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

/*
	TODO:
		- Oauth
		- Bind client ID to user-agent /  (future)
			- Hash IP
			- allow same subnet for mobile

*/

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
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}
func loginHandler(s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		/* ip := ClientIP(r) */

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return
		}

		token, refresh_token, clientID, err := s.Login(r.Context(), req.Email, req.Password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
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

		if err := s.RevokeAll(r.Context(), userID); err != nil {
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

func RegisterRoutes(r chi.Router, db *sql.DB, privateKey *rsa.PrivateKey, PublicKey *rsa.PublicKey, tokenSecret string) {
	repo := users.NewSQLiteRepository(db)
	refreshrepo := auth.NewRefreshRepo(db)
	service := NewService(repo, refreshrepo, privateKey, tokenSecret)

	r.Post("/register", registerHandler(service))
	r.Post("/login", loginHandler(service))
	r.Post("/refresh", refreshHandler(service))
	r.Post("/logout", logoutHandler(service))

	r.Group(func(r chi.Router) {
		r.Use(JWTMiddleware(PublicKey))
		r.Get("/me", meHandler())
		r.Post("/revoke-all", revokeAllHandler(service))
	})
}
