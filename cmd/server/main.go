// @title           AuthAPI
// @version         1.3
// @description     REST API documentation
// @BasePath        /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

// @securityDefinitions.apikey TenantAuth
// @in header
// @name X-Tenant

// @security TenantAuth

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"AuthAPI/main/internal/auth"
	"AuthAPI/main/internal/auth/app"
	"AuthAPI/main/internal/auth/logger"
	luascripts "AuthAPI/main/internal/auth/luascripts"
	"AuthAPI/main/internal/auth/mail"
	"AuthAPI/main/internal/auth/ratelimiter"
	"AuthAPI/main/internal/auth/refresh"
	"AuthAPI/main/internal/auth/tenants"
	"AuthAPI/main/internal/broker"
	"AuthAPI/main/internal/config"
	"AuthAPI/main/internal/db"
	"AuthAPI/main/internal/outbox"
	"AuthAPI/main/internal/users"

	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"
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

	redisoptions, err := config.LoadRedisConfig()
	if err != nil {
		log.Fatalf("failed to load Redis config: %v", err)
		/* log.Fatal(err) */
		/* panic(err) */
	}
	fmt.Printf(
		"Redis addr=%q protocol=%d db=%d\n",
		redisoptions.Addr,
		redisoptions.Protocol,
		redisoptions.DB,
	)

	cfg.Redis = *config.RedisOptionstoConfig(redisoptions)
	ctx := context.Background()

	rdb := redis.NewClient(redisoptions)
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatal(err)
	}

	if err := luascripts.Init(); err != nil {
		log.Fatal(err)
	}

	ratelimiter := ratelimiter.NewRedisLimiter(rdb)

	app := &app.App{
		UserRepo:     users.NewUserRepo(cfg.Database.Driver, database),
		RefreshRepo:  refresh.NewRefreshRepo(cfg.Database.Driver, database),
		EmailRepo:    mail.NewEmailVerificationRepo(cfg.Database.Driver, database),
		Mailer:       &cfg.SMTP,
		PrivateKey:   priv,
		PublicKey:    pub,
		TokenSecret:  tokenSecret,
		OutboxRepo:   outbox.NewOutboxRepo(cfg.Database.Driver, database),
		TenantRepo:   tenants.NewTenantRepo(cfg.Database.Driver, database),
		Logger:       logger,
		Redisclient:  rdb,
		RedisLimiter: &ratelimiter,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var mqBroker broker.Broker
	if cfg.Database.Driver == "postgres" {
		rabbit, err := broker.NewRabbitMQ(cfg.Broker.URL, cfg.Broker.Exchange, logger)
		if err != nil {
			log.Fatalf("failed to connect to rabbitmq: %v", err)
		}
		mqBroker = rabbit
		defer func() {
			if err := mqBroker.Close(); err != nil {
				logger.Error("broker: error during close", "error", err)
			}
		}()

		processor := outbox.NewProcessor(app.OutboxRepo, mqBroker, logger, "outbox-worker-1")
		worker := outbox.NewWorker(processor, outbox.WorkerConfig{}, logger)
		go worker.Run(ctx)
	} else if cfg.Database.Driver == "sqlite" && cfg.Environment == "production" {
		logger.Info("Application running on production mode with sqlite, are you sure of what you're doing?")
	}

	/* nts: TODO: rewire the router initiation to pass on Service instead of creating it within the router,
	also think of passing cfg to the service router for a more elegant way of delivering APP_URL */

	r := config.InitRouter(cfg, pub, logger, app.TenantRepo, func(r chi.Router) {
		auth.RegisterRoutes(*app, r, database, cfg.AppBaseURL)
	})

	srv := &http.Server{
		Addr:              ":8081",
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Debug("Auth service running on :8081")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error(err.Error())
			panic(err)
		}
	}()

	<-ctx.Done()
	logger.Error("shutting down...")
	//rdb.Close()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		error_str := "error during server shutdown: " + err.Error()
		logger.Error(error_str)
	}
}
