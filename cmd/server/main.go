package main

import (
	"log"
	"net/http"

	"AuthAPI/main/internal/auth"
	"AuthAPI/main/internal/auth/mail"
	"AuthAPI/main/internal/auth/refresh"
	"AuthAPI/main/internal/config"
	"AuthAPI/main/internal/db"
	"AuthAPI/main/internal/users"

	"github.com/go-chi/chi/v5"
)

func main() {

	priv, pub, tokenSecret := config.LoadKeys()

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	database, err := db.Open(cfg.Database)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	if err := db.RunMigrations(database, cfg.Database.Driver); err != nil {
		log.Fatal(err)
	}

	//nts todo: migration versioning

	app := &config.App{
		UserRepo:    users.NewUserRepo(cfg.Database.Driver, database),
		RefreshRepo: refresh.NewRefreshRepo(cfg.Database.Driver, database),
		EmailRepo:   mail.NewEmailVerificationRepo(cfg.Database.Driver, database),
		Mailer:      &cfg.SMTP,
		PrivateKey:  priv,
		PublicKey:   pub,
		TokenSecret: tokenSecret,
	}

	r := config.InitRouter(cfg, func(r chi.Router) {
		auth.RegisterRoutes(*app, r)
	})

	log.Println("Auth service running on :8081")
	http.ListenAndServe(":8081", r)
}
