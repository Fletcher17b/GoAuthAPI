package auth

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	"AuthAPI/main/internal/auth/mail"
	"AuthAPI/main/internal/auth/metrics"
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
	app_url    string
}

/*
const (

	maxFailedAttempts = 5
	lockoutWindow     = 15 * time.Minute

)
*/

type EMailLockoutPayload struct {
	Email            string     `json:"email"`
	Username         string     `json:"username"`
	LoggedAttempt_At *time.Time `json:"attempttime"`
	Location         string     `json:"attemptlocation"`
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
	app_url string,

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
		app_url:         app_url,
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
	if err != nil {
		return err
	}

	user := &models.User{
		ID:           userid,
		Email:        email,
		PasswordHash: &hash,
		IsActive:     false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.users.Create(ctx, user); err != nil {
		return wrapUserCreateError(err)
	}

	rawToken := uuid.NewString()
	tokenHash := crypto.HashToken(rawToken, s.tokenSecret)

	tokenid, err := uuid.NewV7()
	if err != nil {
		return err
	}
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
	// nts TODO: here rework here
	go s.mailer.SendVerificationEmail(email, rawToken) //nolint:errcheck

	return nil

}

// nts: TODO: refactor databuilder to return a collapsed struct instead of a bunch of models

type SignUpData struct {
	User                   *models.User
	EmailVerificationToken *models.EmailVerificationToken
	RefreshToken           *models.RefreshToken
	UserCreatedEvent       *models.OutboxEvent
	EmailVerificationEvent *models.OutboxEvent
	plaintoken             string //nolint:unused
}

// signupDataBuilder is a helper function that constructs and fills out the models used in the operation.
// Returns (User, EmailVerificationToken, RefreshToken, OutboxEvent, UserInfo, plainRefreshToken, error) models
func (s *Service) signupDataBuilder(email, username, password, clientID string) (
	*models.User,
	*models.EmailVerificationToken,
	*models.RefreshToken,
	*models.OutboxEvent,
	*models.OutboxEvent,
	*UserInfo,
	string,
	error,
) {
	now := time.Now()

	hash, err := crypto.HashPassword(password)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, "", err
	}

	userID, err := uuid.NewV7()
	if err != nil {
		return nil, nil, nil, nil, nil, nil, "", err
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
		return nil, nil, nil, nil, nil, nil, "", err
	}
	token := &models.EmailVerificationToken{
		ID:        verificationTokenID,
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	familyID, err := uuid.NewV7()
	if err != nil {
		return nil, nil, nil, nil, nil, nil, "", err
	}

	plaintoken, refreshModel, err := GenerateRefreshToken(user.ID, familyID, uuid.Nil, clientID, s.tokenSecret)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, "", err
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
		return nil, nil, nil, nil, nil, nil, "", err
	}

	outboxEvent_createID, err := uuid.NewV7()
	if err != nil {
		return nil, nil, nil, nil, nil, nil, "", err
	}
	outboxEvent_create := &models.OutboxEvent{
		ID:          outboxEvent_createID,
		EventType:   models.UserCreated,
		Payload:     outboxPayload,
		Status:      models.StatusPending,
		NextRetryAt: now,
		CreatedAt:   now,
	}

	outboxEvent_sendmailID, err := uuid.NewV7()
	if err != nil {
		return nil, nil, nil, nil, nil, nil, "", err
	}

	emailPlainToken, EmailVerificationToken, err := GenerateEmailVerificationToken(userID, s.tokenSecret)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, "", err
	}

	verificationurl := VerifyEmailURLConstructor(s.app_url, emailPlainToken)

	emailoutboxPayloadRaw := EmailVerificationRequestPayload{
		UserID:          user.ID,
		Email:           email,
		EventID:         outboxEvent_sendmailID,
		VerificationUrl: verificationurl,
		ExpiresAt:       EmailVerificationToken.ExpiresAt,
	}

	emailoutboxPayloadJson, err := json.Marshal(emailoutboxPayloadRaw)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, "", err
	}

	outboxEvent_sendmail := &models.OutboxEvent{
		ID:          outboxEvent_sendmailID,
		EventType:   models.EmailVerificationRequested,
		Payload:     emailoutboxPayloadJson,
		Status:      models.StatusPending,
		NextRetryAt: now, // nts TODO: why is this here???
		CreatedAt:   now,
	}

	return user, token, refreshModel, outboxEvent_create, outboxEvent_sendmail, &userInfo, plaintoken, nil
}

// signUpTransaction transaction takes the prebuilt models and commits them in a single transaction
func (s *Service) signUpTransaction(
	ctx context.Context,
	user *models.User,
	token *models.EmailVerificationToken,
	refresh *models.RefreshToken,
	outbox *models.OutboxEvent,
	outbox_mail *models.OutboxEvent,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if err := s.users.CreateTx(ctx, tx, user); err != nil {
		return wrapUserCreateError(err)
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
	if err := s.outboxrepo.CreateTx(ctx, tx, outbox_mail); err != nil {
		return err
	}

	return tx.Commit()
}

// signupResponseBuilder builds the JSON response to be returned to the SignupHandler and sent back the requester/client
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

	clientID := GenerateClientID()
	user, emailVerifyToken, refreshToken, outboxEvent, outboxEvent_sendmail, response_userinfo, plaintoken, err := s.signupDataBuilder(email, username, password, clientID)
	if err != nil {
		/* nts */
		return nil, err
	}

	err2 := s.signUpTransaction(ctx, user, emailVerifyToken, refreshToken, outboxEvent, outboxEvent_sendmail)
	if err2 != nil {
		return nil, err2
	}

	metrics.SignupsTotal.WithLabelValues("success").Inc()
	return s.signupResponseBuilder(user, *response_userinfo, plaintoken)

}

func (s *Service) VerifyEmail(ctx context.Context, rawToken string) error {
	tokenHash := crypto.HashToken(rawToken, s.tokenSecret)

	token, err := s.emailVerifyrepo.FindValidByHash(ctx, tokenHash)
	if err != nil {
		return ErrInvalidVerificationToken
	}

	if token.UsedAt != nil || time.Now().After(token.ExpiresAt) {
		return ErrInvalidVerificationToken
	}

	now := time.Now()

	if err := s.emailVerifyrepo.MarkUsed(ctx, token.ID, now); err != nil {
		return err
	}

	return s.users.ActivateUser(ctx, token.UserID)
}

func (s *Service) ResendVerification(ctx context.Context, email string) error {
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return nil
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
	if err != nil {
		return err
	}

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

/*
	nts todo: write Lockout trigger logic
			  also send email notifying loggin
			  also IP catching to send the email correctly:
			  	"Hey user we detected a loggin from {IP} at {time}
				 We wanted to confirm it was you,
				 if it wasnt reset your password here {url}
				"
*/

func (s *Service) Login(ctx context.Context, email, password string) (string, string, string, error) {
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil || user == nil || user.PasswordHash == nil {
		return "", "", "", ErrInvalidCredentials
	}

	if err := crypto.ComparePassword(*user.PasswordHash, password); err != nil {
		return "", "", "", ErrInvalidCredentials
	}
	/*
		if !user.IsActive {
			return "", "", "", fmt.Errorf("login failed: %w", ErrEmailNotVerified)
		}
	*/

	if user.LockedAt != nil {
		return "", "", "", ErrUserLockedout
	}

	access, err := GenerateAccessToken(user.ID, user.Email, s.privateKey)
	if err != nil {
		return "", "", "", err
	}

	clientID := GenerateClientID()

	familyID, err := uuid.NewV7()
	if err != nil {
		return "", "", "", err
	}
	// nts uuid.nil is used here but further down in the repository layer it is converted to nil and stored that way in the DB
	refreshPlain, refreshModel, err := GenerateRefreshToken(user.ID, familyID, uuid.Nil, clientID, s.tokenSecret)
	if err != nil {
		return "", "", "", err
	}

	if err := s.refreshRepo.Create(ctx, refreshModel); err != nil {
		return "", "", "", err
	}

	metrics.LoginAttemptsTotal.WithLabelValues("success").Inc()
	return access, refreshPlain, clientID, nil
}

func (s *Service) rotateHelper(ctx context.Context, refreshToken string) (string, *models.RefreshToken, error) {

	hash := crypto.HashToken(refreshToken, s.tokenSecret)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	old, err := s.refreshRepo.FindbyHash(ctx, tx, hash)
	if err != nil {
		return "", nil, ErrInvalidToken
	}

	if old.ExpiresAt.Before(time.Now()) {
		return "", nil, ErrInvalidToken
	}

	if old.RevokedAt != nil {
		_ = s.refreshRepo.RevokeAllForFamily(ctx, tx, old.FamilyID)
		_ = tx.Commit()
		return "", nil, ErrRefreshReuse
	}

	if err := s.refreshRepo.Revoke(ctx, tx, old.ID); err != nil {
		return "", nil, err
	}

	plain, model, err := GenerateRefreshToken(
		old.UserID,
		old.FamilyID,
		old.ID,
		old.ClientID,
		s.tokenSecret,
	)

	if err != nil {
		return "", nil, err
	}

	if err := s.refreshRepo.CreateTx(ctx, tx, model); err != nil {
		return "", nil, err
	}

	if err := tx.Commit(); err != nil {
		return "", nil, err
	}

	metrics.RefreshReuseDetectedTotal.Inc()
	return plain, model, nil
}

func (s *Service) Refresh(ctx context.Context, refreshToken string) (string, string, time.Time, error) {
	newPlain, newModel, err := s.rotateHelper(ctx, refreshToken)
	if err != nil {
		return "", "", time.Time{}, err
	}

	user, err := s.users.FindByID(ctx, newModel.UserID)
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

	return access, newPlain, newModel.ExpiresAt, nil
}

func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	hash := crypto.HashToken(refreshToken, s.tokenSecret)

	rt, err := s.refreshRepo.FindValidByHash(ctx, hash)
	if err != nil {
		return ErrInvalidToken
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		_ = tx.Rollback()
	}()

	if err := s.refreshRepo.Revoke(ctx, tx, rt.ID); err != nil {
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (s *Service) RevokeAll(ctx context.Context, userID uuid.UUID) error {
	return s.refreshRepo.RevokeAllForUser(ctx, userID)
}

/*
requires a JWT session and a user

implement IP picking and email send
*/

func (s *Service) ChangePasword(ctx context.Context, req ChangePasswordRequest) error {

	/* Add here JWT functionality */

	user, err := s.users.FindByEmail(ctx, req.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrInvalidCredentials
		}
		return err
	}

	if err := crypto.ComparePassword(*user.PasswordHash, req.OldPassword); err != nil {
		return ErrInvalidCredentials
	}

	hashedpassword, err := crypto.HashPassword(req.NewPassword)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	err = s.users.ChangePasword(ctx, tx, user.ID, hashedpassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrInvalidCredentials
		}
		return err
	}

	outboxPayload, err := json.Marshal(req)
	if err != nil {
		return err
	}

	outboxEvent_createID, err := uuid.NewV7()
	if err != nil {
		return err
	}

	now := time.Now()

	newoutboxevent := &models.OutboxEvent{
		ID:          outboxEvent_createID,
		EventType:   models.EmailUserLogin,
		Payload:     outboxPayload,
		Status:      models.StatusPending,
		CreatedAt:   now,
		NextRetryAt: now.Add(time.Minute * 5),
	}

	err = s.outboxrepo.CreateTx(ctx, tx, newoutboxevent)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		// nts: TODO: add logger here
		println("db error: ", err.Error())
		return nil
	}
	return nil

}

func (s *Service) RequestResetPassword(ctx context.Context, email string) error {
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrInvalidCredentials
		}
		return err
	}

	outboxEvent_ID, err := uuid.NewV7()
	if err != nil {
		return err
	}

	now := time.Now()

	rawpayload, err := json.Marshal(user.Email)
	if err != nil {
		return err
	}

	newoutbox := &models.OutboxEvent{
		ID:          outboxEvent_ID,
		EventType:   models.PasswordResetRequested,
		Status:      models.StatusPending,
		Payload:     rawpayload,
		CreatedAt:   now,
		NextRetryAt: now.Add(time.Minute * 5),
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	err = s.outboxrepo.CreateTx(ctx, tx, newoutbox)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		// nts: TODO: add logger here
		println("db error: ", err.Error())
		return nil
	}

	return nil
}

func (s *Service) ResetPassword(ctx context.Context, email string) {

}

// Helpers

func wrapUserCreateError(err error) error {
	if err == nil {
		return nil
	}
	if isUniqueConstraintError(err) {
		return ErrEmailAlreadyExists
	}
	return err
}

func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate")
}
