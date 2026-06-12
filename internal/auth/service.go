package auth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/google/uuid"

	"AuthAPI/main/internal/auth/mail"
	auth "AuthAPI/main/internal/auth/refresh"
	"AuthAPI/main/internal/crypto"
	"AuthAPI/main/internal/models"
	"AuthAPI/main/internal/users"
)

/*
const ErrInvalidCredentials error.err = "Invalid Credentials"
const ErrInvalidToken string = "Invalid Token"
*/
type Service struct {
	users       users.Repository
	refreshRepo auth.RefreshTokenRepository

	emailVerifyrepo mail.EmailVerificationRepository
	mailer          mail.Mailer

	privateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey

	tokenSecret string
}

func NewService(
	users users.Repository,
	refreshRepo auth.RefreshTokenRepository,

	/* emailVerifyrepo mail.EmailVerificationRepository,
	mailer mail.Mailer, */

	privateKey *rsa.PrivateKey,
	tokenSecret string,
) *Service {
	return &Service{
		users:       users,
		refreshRepo: refreshRepo,
		/* emailVerifyrepo: emailVerifyrepo,
		mailer:          mailer, */
		privateKey:  privateKey,
		tokenSecret: tokenSecret,
	}
}

func (s *Service) Register(ctx context.Context, email, password string) error {
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return err
	}

	now := time.Now()

	user := &models.User{
		ID:           uuid.NewString(),
		Email:        email,
		PasswordHash: &hash,
		IsActive:     false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	return s.users.Create(ctx, user)
}

/*
	TODO: add ip binding implementation here
*/

func (s *Service) Login(ctx context.Context, email, password string) (string, string, string, error) {

	user, err := s.users.FindByEmail(ctx, email)
	if err != nil || user == nil || user.PasswordHash == nil {
		return "", "", "", fmt.Errorf("login failed: %w", ErrInvalidCredentials)
	}

	if err := crypto.ComparePassword(*user.PasswordHash, password); err != nil {
		return "", "", "", fmt.Errorf("login failed: %w", ErrInvalidCredentials)
	}

	access, err := GenerateAccessToken(user.ID, user.Email, s.privateKey)
	if err != nil {
		println("error point: ")
		return "", "", "", err
	}

	refreshPlain, refreshModel, err := generateRefreshToken(user.ID, s.tokenSecret)
	if err != nil {
		println("error point 2")
		return "", "", "", err
	}

	clientID := generateClientID()

	if err := s.refreshRepo.Create(ctx, refreshModel); err != nil {
		println("error point 3")
		return "", "", "", err
	}

	return access, refreshPlain, clientID, nil
}

func (s *Service) Refresh(ctx context.Context, refreshToken string) (string, string, time.Time, error) {

	hash := crypto.HashToken(refreshToken, s.tokenSecret)

	old, err := s.refreshRepo.FindValidByHash(ctx, hash)
	if err != nil {
		return "", "", time.Time{}, ErrInvalidToken
	}

	/* // 🔒 IP binding enforcement
	if old.IPAddress != currentIP {
		_ = s.refreshRepo.Revoke(ctx, old.ID)
		return "", "", ErrIPMismatch
	} */

	_ = s.refreshRepo.Revoke(ctx, old.ID)

	user, err := s.users.FindByID(ctx, old.UserID)
	if err != nil {
		return "", "", time.Time{}, err
	}

	access, err := GenerateAccessToken(
		user.ID,
		user.Email,
		s.privateKey,
	)
	if err != nil {
		return "", "", time.Time{}, err
	}

	newPlain, newModel, err :=
		generateRefreshToken(user.ID, s.tokenSecret)
	if err != nil {
		return "", "", time.Time{}, err
	}

	if err := s.refreshRepo.Create(ctx, newModel); err != nil {
		return "", "", time.Time{}, err
	}

	return access, newPlain, newModel.ExpiresAt, nil
}

func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	hash := crypto.HashToken(refreshToken, s.tokenSecret)

	rt, err := s.refreshRepo.FindValidByHash(ctx, hash)
	if err != nil {
		return ErrInvalidToken
	}

	return s.refreshRepo.Revoke(ctx, rt.ID)
}

func (s *Service) RevokeAll(ctx context.Context, userID string) error {
	return s.refreshRepo.RevokeAllForUser(ctx, userID)
}
