package config

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func InitRouter(
	cfg *Config,
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
	registerBusinessRoutes(r)

	return r
}
