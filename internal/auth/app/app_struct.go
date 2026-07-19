package app

import (
	"AuthAPI/main/internal/auth/mail"
	"AuthAPI/main/internal/auth/refresh"
	"AuthAPI/main/internal/outbox"
	"AuthAPI/main/internal/users"
	"crypto/rsa"
)

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
