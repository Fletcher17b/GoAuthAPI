package auth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"AuthAPI/main/internal/auth/mail"
	auth "AuthAPI/main/internal/auth/refresh"
	"AuthAPI/main/internal/crypto"
	"AuthAPI/main/internal/models"
	"AuthAPI/main/internal/outbox"
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

	outboxrepo outbox.OutboxRepo
}

func NewService(
	users users.Repository,
	refreshRepo auth.RefreshTokenRepository,

	emailVerifyrepo mail.EmailVerificationRepository,
	mailer mail.Mailer,

	privateKey *rsa.PrivateKey,
	tokenSecret string,

	outboxrepo outbox.OutboxRepo,

) *Service {
	return &Service{
		users:           users,
		refreshRepo:     refreshRepo,
		emailVerifyrepo: emailVerifyrepo,
		mailer:          mailer,
		privateKey:      privateKey,
		tokenSecret:     tokenSecret,
		outboxrepo:      outboxrepo,
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

	userid, err := uuid.NewV7()
	user := &models.User{
		ID:           userid,
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

	tokenid, err := uuid.NewV7()
	token := &models.EmailVerificationToken{
		ID:        tokenid,
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

func (s *Service) SignupService(ctx context.Context, email, username, password string) (*SignupResponseRefactor, error) {

	hash, err := crypto.HashPassword(password)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	user_id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

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

	verificationtokenID, err := uuid.NewV7()
	token := &models.EmailVerificationToken{
		ID:        verificationtokenID,
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	if err := s.emailVerifyrepo.Create(ctx, token); err != nil {
		return nil, err
	}

	//var SignupResponseTokens SignupResponseTokens
	//var SignupResponseUserInfo SignupResponseUserInfo

	UserInfo := SignupResponseUserInfo{
		UserID:    user_id,
		Email:     email,
		Username:  username,
		Verified:  false,
		CreatedAt: now,
	}

	atoken, err := GenerateAccessToken(user_id, email, s.privateKey)
	if err != nil {
		log.Println("Panic: Failed to created Access token for user: ", user_id)
	}

	clientID := generateClientID()
	rtoken, refreshModel, err := generateRefreshToken(user_id, clientID, s.tokenSecret)
	if err := s.refreshRepo.Create(ctx, refreshModel); err != nil {
		log.Println("Panic: Failed to created refresh token for user: ", user_id)
		return nil, err
	}

	tokens := SignupResponseTokens{
		AccessToken:  atoken,
		RefreshToken: rtoken,
		TokenType:    "bearer",
	}

	signupresponse := SignupResponseRefactor{
		UserToken: tokens,
		UserInfo:  UserInfo,
	}

	outbox_payload, err := json.Marshal(UserInfo)

	outbox_eventID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	outbox_event := &models.OutboxEvent{
		ID:          outbox_eventID,
		EventType:   models.UserCreated,
		Payload:     outbox_payload,
		Headers:     nil,
		Status:      models.StatusPending,
		NextRetryAt: time.Now(),
		CreatedAt:   now,
	}

	return &signupresponse, nil

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

	tokenid, err := uuid.NewV7()

	token := &models.EmailVerificationToken{
		ID:        tokenid,
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
	// nts todo: Reuse Detection
	// findbyvalidHash currently only sends tokens that do not have revoked_at as NULL,
	// refactor it to send back even if it is null, then check date and compare to see token reuse
	/* if !old.RevokedAt.IsZero() {
			// 🔒 IP binding enforcement
			if old.IPAddress != currentIP {
				_ = s.refreshRepo.Revoke(ctx, old.ID)

				// Sent "attempted use of token" log// notification logic through RabbitMQ here

				return "", "", ErrIPMismatch
			}

		return "", "", time.Time{}, ErrInvalidToken
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

func (s *Service) RevokeAll(ctx context.Context, userID uuid.UUID) error {
	return s.refreshRepo.RevokeAllForUser(ctx, userID)
}
