package main

import (
	"context"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	/*
		var mqBroker broker.Broker
		if cfg.Database.Driver == "postgres" {
			rabbit, err := broker.NewRabbitMQ(cfg.Broker.URL, cfg.Broker.Exchange)
			if err != nil {
				log.Fatalf("failed to connect to rabbitmq: %v", err)
			}
			mqBroker = rabbit
			defer mqBroker.Close()

			processor := outbox.NewProcessor(app.OutboxRepo, mqBroker)
			worker := outbox.NewWorker(processor, outbox.WorkerConfig{})
			go worker.Run(ctx)
		} */

	r := config.InitRouter(cfg, func(r chi.Router) {
		auth.RegisterRoutes(*app, r, database)
	})
	srv := &http.Server{Addr: ":8081", Handler: r}

	go func() {
		log.Println("Auth service running on :8081")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server exited: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("error during server shutdown: %v", err)
	}
}
