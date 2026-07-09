package auth

import (
	"context"
	"crypto/rsa"
	"errors"
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

/*
	Todo: Activate user method on repo
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

	emailVerifyrepo mail.EmailVerificationRepository,
	mailer mail.Mailer,

	privateKey *rsa.PrivateKey,
	tokenSecret string,
) *Service {
	return &Service{
		users:           users,
		refreshRepo:     refreshRepo,
		emailVerifyrepo: emailVerifyrepo,
		mailer:          mailer,
		privateKey:      privateKey,
		tokenSecret:     tokenSecret,
	}
}

func (s *Service) Register(ctx context.Context, email, password string) error {
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return err
	}

	if s.emailVerifyrepo == nil {
		panic("emailVerifyrepo not configured")
	}
	if s.mailer == nil {
		panic("mailer not configured")
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

	if err := s.users.Create(ctx, user); err != nil {
		return err
	}

	rawToken := uuid.NewString()
	tokenHash := crypto.HashToken(rawToken, s.tokenSecret)

	token := &models.EmailVerificationToken{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	if err := s.emailVerifyrepo.Create(ctx, token); err != nil {
		return err
	}

	// TODO: Introduce WorkerPool here

	go s.mailer.SendVerificationEmail(email, rawToken)

	return nil

}

func (s *Service) SignupService(ctx context.Context, email, username, password string) (*SignupResponse, error) {

	hash, err := crypto.HashPassword(password)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	user_id := uuid.NewString()

	user := &models.User{
		ID:           user_id,
		Email:        email,
		PasswordHash: &hash,
		IsActive:     false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}

	rawToken := uuid.NewString()
	tokenHash := crypto.HashToken(rawToken, s.tokenSecret)

	token := &models.EmailVerificationToken{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	if err := s.emailVerifyrepo.Create(ctx, token); err != nil {
		return nil, err
	}

	go s.mailer.SendVerificationEmail(user.Email, rawToken)

	var response SignupResponse

	response.UserMetadata.Status = "provisioning"

	response.UserMetadata.Email = email
	response.UserMetadata.UserID = user_id
	response.UserMetadata.Username = username

	return &response, nil
}

func (s *Service) VerifyEmail(ctx context.Context, rawToken string) error {
	tokenHash := crypto.HashToken(rawToken, s.tokenSecret)

	token, err := s.emailVerifyrepo.FindValidByHash(ctx, tokenHash)
	if err != nil {
		return errors.New("invalid or expired token")
	}

	if token.UsedAt != nil || time.Now().After(token.ExpiresAt) {
		return errors.New("token invalid")
	}

	now := time.Now()

	if err := s.emailVerifyrepo.MarkUsed(ctx, token.ID, now); err != nil {
		return err
	}

	// 	_ = s.emailVerifyrepo.DeleteByUserID(ctx, token.UserID)

	return s.users.ActivateUser(ctx, token.UserID)
}

func (s *Service) ResendVerification(ctx context.Context, email string) error {
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return err
	}

	// No matching account, or already verified: don't reveal which case
	// this is, just behave as if the resend succeeded.
	if user == nil || user.IsActive {
		return nil
	}

	_ = s.emailVerifyrepo.DeleteByUserID(ctx, user.ID)

	rawToken := uuid.NewString()
	tokenHash := crypto.HashToken(rawToken, s.tokenSecret)

	token := &models.EmailVerificationToken{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	if err := s.emailVerifyrepo.Create(ctx, token); err != nil {
		return err
	}

	return s.mailer.SendVerificationEmail(user.Email, rawToken)
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
	/*
		if !user.IsActive {
			return "", "", "", fmt.Errorf("login failed: %w", ErrEmailNotVerified)
		} */

	access, err := GenerateAccessToken(user.ID, user.Email, s.privateKey)
	if err != nil {
		println("error point: ")
		return "", "", "", err
	}

	clientID := generateClientID()

	refreshPlain, refreshModel, err := generateRefreshToken(user.ID, clientID, s.tokenSecret)
	if err != nil {
		println("error point 2")
		return "", "", "", err
	}

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

	if !old.RevokedAt.IsZero() {
		/*
			// 🔒 IP binding enforcement
			if old.IPAddress != currentIP {
				_ = s.refreshRepo.Revoke(ctx, old.ID)

				// Sent "attempted use of token" log// notification logic through RabbitMQ here

				return "", "", ErrIPMismatch
			}
		*/
		return "", "", time.Time{}, ErrInvalidToken
	}

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
		generateRefreshToken(user.ID, old.ClientID, s.tokenSecret)
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
