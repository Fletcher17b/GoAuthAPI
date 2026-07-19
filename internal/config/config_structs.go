package config

import (
	"AuthAPI/main/internal/auth/mail"
	"AuthAPI/main/internal/auth/refresh"
	"AuthAPI/main/internal/outbox"
	"AuthAPI/main/internal/users"
	"crypto/rsa"
)

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

type Config struct {
	AppBaseURL           string
	SMTP                 mail.SMTPMailer
	CORS_ALLOWED_ORIGINS []string

	Database DatabaseConfig
}

type SQLiteConfig struct {
	Path string
}

type PostgresConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	/* SSLMode  string */
}

type DatabaseConfig struct {
	Driver       string
	SqliteConf   SQLiteConfig
	PostgresConf PostgresConfig
}

type App struct {
	UserRepo    users.Repository
	RefreshRepo refresh.RefreshTokenRepository
	EmailRepo   mail.EmailVerificationRepository
	Mailer      *mail.SMTPMailer
	PrivateKey  *rsa.PrivateKey
	PublicKey   *rsa.PublicKey
	TokenSecret string
	OutboxRepo  outbox.OutboxRepo
}
