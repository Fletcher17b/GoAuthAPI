package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type ctxKey string

const ContextRequestID ctxKey = "request_id"

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

			ctx := context.WithValue(r.Context(), ContextUserID, claims.UserID)
			ctx = context.WithValue(ctx, ContextEmail, claims.Email)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
