package main

import (
	"log"
	"net/http"

	"AuthAPI/main/internal/auth"
	"AuthAPI/main/internal/auth/app"
	"AuthAPI/main/internal/auth/mail"
	"AuthAPI/main/internal/auth/refresh"
	"AuthAPI/main/internal/config"
	"AuthAPI/main/internal/db"
	"AuthAPI/main/internal/outbox"
	"AuthAPI/main/internal/users"

	"github.com/go-chi/chi/v5"
)

func main() {

	priv, pub, err := config.LoadKeys()
	if err != nil {
		log.Fatal(err)
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	tokenSecret, err := config.LoadTokenSecret()
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	database, err := db.Open(cfg.Database)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	//nts todo: migration versioning

	app := &app.App{
		UserRepo:    users.NewUserRepo(cfg.Database.Driver, database),
		RefreshRepo: refresh.NewRefreshRepo(cfg.Database.Driver, database),
		EmailRepo:   mail.NewEmailVerificationRepo(cfg.Database.Driver, database),
		Mailer:      &cfg.SMTP,
		PrivateKey:  priv,
		PublicKey:   pub,
		TokenSecret: tokenSecret,
		OutboxRepo:  outbox.NewOutboxRepoAuxiliary(cfg.Database.Driver, database),
	}

	r := config.InitRouter(cfg, func(r chi.Router) {
		auth.RegisterRoutes(*app, r, database)
	})

	log.Println("Auth service running on :8081")

	if err := http.ListenAndServe(":8081", r); err != nil {
		log.Fatalf("HTTP server exited: %v", err)
	}
}
