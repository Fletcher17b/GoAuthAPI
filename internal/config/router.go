package config

import (
	"AuthAPI/main/internal/auth"
	"crypto/rsa"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func InitRouter(
	cfg *Config,
	pub *rsa.PublicKey,
	logger *slog.Logger,
	registerBusinessRoutes func(r chi.Router),
) *chi.Mux {

	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			next.ServeHTTP(w, r)
		})
	})

	corsOptions := LoadCors(*cfg)
	r.Use(corsOptions.Handler)
	r.Use(auth.LoggingMiddleware(logger))
	//r.Use(auth.JWTMiddleware(pub))
	r.Handle("/metrics", promhttp.Handler())
	registerBusinessRoutes(r)

	return r
}
