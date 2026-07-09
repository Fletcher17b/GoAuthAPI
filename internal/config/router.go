package config

import (
	"AuthAPI/main/internal/auth"
	"crypto/rsa"
	"database/sql"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func InitRouter(
	db *sql.DB,
	priv *rsa.PrivateKey,
	pub *rsa.PublicKey,
	tokenSecret string,
	cfg Config,
) *chi.Mux {

	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			next.ServeHTTP(w, r)
		})
	})

	corsOptions := LoadCors(cfg)

	r.Use(corsOptions.Handler)

	auth.RegisterRoutes(r, db, priv, pub, tokenSecret, &cfg.SMTP)
	return r
}
