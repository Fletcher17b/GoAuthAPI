package auth

import (
	"context"
	"crypto/rsa"
	"database/sql"
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
	Todo: Switch service struct to use app struct
*/

type Service struct {
	db *sql.DB

	users       users.Repository
	refreshRepo auth.RefreshTokenRepository

	emailVerifyrepo mail.EmailVerificationRepository
	mailer          mail.Mailer

	privateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey

	tokenSecret string

	outboxrepo outbox.OutboxRepo
}

type SignUpDataDelagateStruct struct {
}

func NewService(
	users users.Repository,
	refreshRepo auth.RefreshTokenRepository,

	emailVerifyrepo mail.EmailVerificationRepository,
	mailer mail.Mailer,

	privateKey *rsa.PrivateKey,
	tokenSecret string,

	outboxrepo outbox.OutboxRepo,
	db *sql.DB,

) *Service {
	return &Service{
		users:           users,
		refreshRepo:     refreshRepo,
		emailVerifyrepo: emailVerifyrepo,
		mailer:          mailer,
		privateKey:      privateKey,
		tokenSecret:     tokenSecret,
		outboxrepo:      outboxrepo,
		db:              db,
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

func (s *Service) signupDataBuilder(email, username, password, clientID string) (
	*models.User,
	*models.EmailVerificationToken,
	*models.RefreshToken,
	*models.OutboxEvent,
	*UserInfo,
	string,
	error,
) {
	now := time.Now()

	hash, err := crypto.HashPassword(password)
	if err != nil {
		return nil, nil, nil, nil, nil, "", err
	}

	userID, err := uuid.NewV7()
	if err != nil {
		return nil, nil, nil, nil, nil, "", err
	}
	user := &models.User{
		ID:           userID,
		Email:        email,
		PasswordHash: &hash,
		IsActive:     false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	rawToken := uuid.NewString()
	tokenHash := crypto.HashToken(rawToken, s.tokenSecret)
	verificationTokenID, err := uuid.NewV7()
	if err != nil {
		return nil, nil, nil, nil, nil, "", err
	}
	token := &models.EmailVerificationToken{
		ID:        verificationTokenID,
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	plaintoken, refreshModel, err := generateRefreshToken(user.ID, clientID, s.tokenSecret)
	if err != nil {
		return nil, nil, nil, nil, nil, "", err
	}

	userInfo := UserInfo{
		UserID:    user.ID,
		Email:     email,
		Username:  username,
		Verified:  false,
		CreatedAt: now,
	}
	outboxPayload, err := json.Marshal(userInfo)
	if err != nil {
		return nil, nil, nil, nil, nil, "", err
	}

	outboxEventID, err := uuid.NewV7()
	if err != nil {
		return nil, nil, nil, nil, nil, "", err
	}
	outboxEvent := &models.OutboxEvent{
		ID:          outboxEventID,
		EventType:   models.UserCreated,
		Payload:     outboxPayload,
		Status:      models.StatusPending,
		NextRetryAt: now,
		CreatedAt:   now,
	}

	return user, token, refreshModel, outboxEvent, &userInfo, plaintoken, nil
}

func (s *Service) signIpTransaction(
	ctx context.Context,
	user *models.User,
	token *models.EmailVerificationToken,
	refresh *models.RefreshToken,
	outbox *models.OutboxEvent,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := s.users.CreateTx(ctx, tx, user); err != nil {
		return err
	}
	if err := s.emailVerifyrepo.CreateTx(ctx, tx, token); err != nil {
		return err
	}
	if err := s.refreshRepo.CreateTx(ctx, tx, refresh); err != nil {
		return err
	}
	if err := s.outboxrepo.CreateTx(ctx, tx, outbox); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Service) signupResponseBuilder(user *models.User, userinfo UserInfo, refreshToken string) (*SignupResponseRefactor, error) {
	accessToken, err := GenerateAccessToken(user.ID, user.Email, s.privateKey)
	if err != nil {
		return nil, err
	}

	return &SignupResponseRefactor{
		UserToken: SignupResponseTokens{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			TokenType:    "bearer",
		},
		UserInfo: userinfo,
	}, nil
}

func (s *Service) SignupService(ctx context.Context, email, username, password string) (*SignupResponseRefactor, error) {

	clientID := generateClientID()
	user, emailVerifyToken, refreshToken, outboxEvent, response_userinfo, plaintoken, err := s.signupDataBuilder(email, username, password, clientID)
	if err != nil {
		log.Println("Failure in Singin UP user: ", err)
		return nil, err
	}

	err2 := s.signIpTransaction(ctx, user, emailVerifyToken, refreshToken, outboxEvent)
	if err2 != nil {
		log.Println("Failure in Singin UP user: ", err2)
		return nil, err2
	}

	return s.signupResponseBuilder(user, *response_userinfo, plaintoken)

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
