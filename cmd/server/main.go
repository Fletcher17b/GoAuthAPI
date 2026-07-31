// @title           AuthAPI
// @version         1.2
// @description     REST API documentation
// @BasePath        /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

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
	"AuthAPI/main/internal/auth/logger"
	"AuthAPI/main/internal/auth/mail"
	"AuthAPI/main/internal/auth/refresh"
	"AuthAPI/main/internal/config"
	"AuthAPI/main/internal/db"
	"AuthAPI/main/internal/outbox"
	"AuthAPI/main/internal/users"

	"github.com/go-chi/chi/v5"
)

func main() {

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to log config: %v ", err)
	}

	logger := logger.New(cfg.Environment, cfg.LogLevel)
	logger.Info("config loaded", "env", cfg.Environment, "db_driver", cfg.Database.Driver)

	priv, pub, err := config.LoadKeys()
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
		Logger:      logger,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	/* var mqBroker broker.Broker
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
	} else if cfg.Database.Driver == "sqlite" && cfg.Environment == "production" {
		logger.Info("Application running on production mode with sqlite, are you sure of what you're doing?")
	} */

	r := config.InitRouter(cfg, pub, logger, func(r chi.Router) {
		auth.RegisterRoutes(*app, r, database)

	})

	srv := &http.Server{Addr: ":8081", Handler: r}

	go func() {
		logger.Debug("Auth service running on :8081")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error(err.Error())
			panic(err)
		}
	}()

	<-ctx.Done()
	logger.Error("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		error_str := "error during server shutdown: " + err.Error()
		logger.Error(error_str)
	}
}
