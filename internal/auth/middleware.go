package auth

import (
	"AuthAPI/main/internal/auth/ratelimiter"
	"AuthAPI/main/internal/auth/tenants"
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type ctxKey string

const ContextRequestID ctxKey = "request_id"

const TenantHeader = "X-Tenant"

type DeviceInfo struct {
	ID        string
	UserAgent string
	IP        string
}

const deviceCookie = "device_id"

func deviceFromRequest(w http.ResponseWriter, r *http.Request) DeviceInfo {
	id := strings.TrimSpace(r.Header.Get("X-Device-ID"))
	if id == "" {
		if c, err := r.Cookie(deviceCookie); err == nil {
			id = c.Value
		}
	}
	if _, err := uuid.Parse(id); err != nil { // reject junk / oversized values
		id = uuid.NewString()
		http.SetCookie(w, &http.Cookie{
			Name:     deviceCookie,
			Value:    id,
			Path:     "/",
			MaxAge:   400 * 24 * 3600,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}
	ua := r.UserAgent()
	if len(ua) > 256 {
		ua = ua[:256]
	}
	return DeviceInfo{ID: id, UserAgent: ua, IP: ClientIP(r)}
}
func RequestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(ContextRequestID).(string); ok {
		return id
	}
	return ""
}

func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		/*
			nts: I dont think requests are gonna have request from the send point so worth
				 seeing if its better to assign it from here
		*/
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			id, err := uuid.NewV7()
			if err != nil {
				reqID = uuid.NewString()
			} else {
				reqID = id.String()
			}
		}
		w.Header().Set("X-Request-ID", reqID)

		ctx := context.WithValue(r.Context(), ContextRequestID, reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func LoggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			h.ServeHTTP(ww, r)

			logger.Info(
				"HTTP request",
				"request_id", RequestIDFromContext(r.Context()),
				"method", r.Method,
				"route", r.URL.Path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration", time.Since(start).String(),
			)
		})
	}
}

func JWTMiddleware(pub *rsa.PublicKey) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, "missing token", http.StatusUnauthorized)
				return
			}

			tokenStr := strings.TrimPrefix(auth, "Bearer ")

			token, err := jwt.ParseWithClaims(
				tokenStr, &Claims{},
				func(t *jwt.Token) (any, error) {
					if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
						return nil, errors.New("unexpected signing method")
					}
					return pub, nil
				},
			)

			if err != nil || !token.Valid {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(*Claims)
			if !ok {
				http.Error(w, "invalid claims", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), ContextUserID, claims.UserID.String())
			ctx = context.WithValue(ctx, ContextEmail, claims.Email)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func TenantMiddleware(repo tenants.TenantRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantName := strings.TrimSpace(r.Header.Get(TenantHeader))
			if tenantName == "" {
				http.Error(w, ErrTenantHeaderMissing.Error(), http.StatusBadRequest)
				return
			}

			tenant, err := repo.FindByTenantName(r.Context(), tenantName)
			if err != nil {
				http.Error(w, ErrTenantNotFound.Error(), http.StatusUnauthorized)
				return
			}

			if !tenant.IsActive() {
				http.Error(w, ErrTenantInactive.Error(), http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), ContextTenant, tenant)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RecovererMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error(
						"panic recovered",
						"request_id", RequestIDFromContext(r.Context()),
						"route", r.URL.Path,
						"method", r.Method,
						"panic", rec,
						"stack", string(debug.Stack()),
					)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error": "internal server error",
					})
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func peekEmail(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	var req struct {
		Email string `json:"email"`
	}
	_ = json.Unmarshal(body, &req)
	return req.Email
}

func RateLimitMiddleware(
	limiter ratelimiter.RedisLimiter,
	logger *slog.Logger,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ClientIP(r)

			var checkErr error
			switch r.URL.Path {
			case "/auth/login":
				checkErr = limiter.CheckLogin(r.Context(), ip, peekEmail(r))
			case "/auth/signup":
				checkErr = limiter.CheckSignup(r.Context(), ip)
			case "/auth/send-resetemail":
				checkErr = limiter.CheckPasswordResetRequest(r.Context(), ip, peekEmail(r))
			default:
				next.ServeHTTP(w, r)
				return
			}

			if checkErr != nil {
				if errors.Is(checkErr, ratelimiter.ErrRateLimited) {
					writeJSON(w, http.StatusTooManyRequests, ErrorResponse{
						Error: "too many attempts, try again later",
					})
					return
				}
				logger.Error("rate limiter check failed", "path", r.URL.Path, "error", checkErr)
			}

			next.ServeHTTP(w, r)
		})
	}
}
