package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"AuthAPI/main/internal/auth"
	"AuthAPI/main/internal/auth/mail"
	"AuthAPI/main/internal/config"
	"AuthAPI/main/internal/db"
)

func main() {

	database, err := db.Open("auth.db")
	if err != nil {
		log.Fatal(err)
	}

	/* if err := db.RunMigrations(database, "migrations/001_init.sql"); err != nil {
		log.Fatal(err)
	} */

	// jwtSecret := []byte("dev-jwt-secret")
	tokenSecret := "dev-refresh-secret"

	priv, err := auth.LoadPrivateKey("private.pem")
	if err != nil {
		log.Fatalf("failed to load private key: %v", err)
	}

	pub, err := auth.LoadPublicKey("public.pem")
	if err != nil {
		log.Fatalf("failed to load public key: %v", err)
	}

	r := chi.NewRouter()

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	mailer := &mail.SMTPMailer{
		Host:     cfg.SMTP.Host,
		Port:     cfg.SMTP.Port,
		Username: cfg.SMTP.Username,
		Password: cfg.SMTP.Password,
		From:     cfg.SMTP.From,
		BaseURL:  cfg.AppBaseURL,
	}

	auth.RegisterRoutes(r, database, priv, pub, tokenSecret, mailer)

	log.Println("Auth service running on :8080")
	http.ListenAndServe(":8080", r)
}
