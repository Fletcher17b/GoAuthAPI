package main

import (
	"log"
	"net/http"

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

	tokenSecret := "dev-refresh-secret"

	priv, pub := config.LoadKeys()

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	r := config.InitRouter(database, priv, pub, tokenSecret, *cfg)

	log.Println("Auth service running on :8081")
	http.ListenAndServe(":8081", r)
}
