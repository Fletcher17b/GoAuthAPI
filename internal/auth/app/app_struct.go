package app

import (
	"AuthAPI/main/internal/auth/mail"
	"AuthAPI/main/internal/auth/ratelimiter"
	"AuthAPI/main/internal/auth/refresh"
	"AuthAPI/main/internal/auth/tenants"
	"AuthAPI/main/internal/outbox"
	"AuthAPI/main/internal/users"
	"crypto/rsa"
	"log/slog"

	"github.com/redis/go-redis/v9"
)

type App struct {
	UserRepo     users.Repository
	RefreshRepo  refresh.RefreshTokenRepository
	EmailRepo    mail.EmailVerificationRepository
	Mailer       *mail.SMTPMailer
	PrivateKey   *rsa.PrivateKey
	PublicKey    *rsa.PublicKey
	TokenSecret  string
	OutboxRepo   outbox.OutboxRepo
	TenantRepo   tenants.TenantRepository
	Logger       *slog.Logger
	Redisclient  *redis.Client
	RedisLimiter *ratelimiter.RedisLimiter
}
