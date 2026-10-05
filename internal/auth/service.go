package auth

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"AuthAPI/main/internal/auth/mail"
	"AuthAPI/main/internal/auth/metrics"
	"AuthAPI/main/internal/auth/ratelimiter"
	auth "AuthAPI/main/internal/auth/refresh"
	"AuthAPI/main/internal/auth/tenants"
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
	tenantRepo  tenants.TenantRepository

	emailVerifyrepo mail.EmailVerificationRepository
	mailer          mail.Mailer

	privateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey

	tokenSecret string

	outboxrepo outbox.OutboxRepo
	app_url    string

	rateLimiter ratelimiter.RedisLimiter
}

/*
const (

	maxFailedAttempts = 5
	lockoutWindow     = 15 * time.Minute

)
*/
const suspiciousLoginNotifyAt = 5

func NewService(
	users users.Repository,
	refreshRepo auth.RefreshTokenRepository,
	tenantRepo tenants.TenantRepository,

	emailVerifyrepo mail.EmailVerificationRepository,
	mailer mail.Mailer,

	privateKey *rsa.PrivateKey,
	tokenSecret string,

	outboxrepo outbox.OutboxRepo,
	db *sql.DB,
	app_url string,

	rateLimiter ratelimiter.RedisLimiter,

) *Service {
	return &Service{
		users:           users,
		refreshRepo:     refreshRepo,
		emailVerifyrepo: emailVerifyrepo,
		tenantRepo:      tenantRepo,
		mailer:          mailer,
		privateKey:      privateKey,
		tokenSecret:     tokenSecret,
		outboxrepo:      outboxrepo,
		db:              db,
		app_url:         app_url,
		rateLimiter:     rateLimiter,
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

	// nts: Outdated endpoint no refactor needed
	go s.mailer.SendVerificationEmail(email, rawToken) //nolint:errcheck

	return nil

}

// nts: TODO: refactor databuilder to return a collapsed struct instead of a bunch of models

type SignUpDataBundle struct {
	User                   *models.User
	EmailVerificationToken *models.EmailVerificationToken
	RefreshToken           *models.RefreshToken
	UserCreatedEvent       *models.OutboxEvent
	EmailVerificationEvent *models.OutboxEvent
	UserInfoDTO            *UserInfo

	PlainRefreshToken string
	PlainEmailToken   string
}

// signupDataBuilder is a helper function that constructs and fills out the models used in the operation.
// Returns (User, EmailVerificationToken, RefreshToken, OutboxEvent, UserInfo, plainRefreshToken, error) models
func (s *Service) signUpDataBuilder(
	email, username, password, clientID, tenantN string,
	tenantID uuid.UUID,
) (*SignUpDataBundle, error) {

	now := time.Now()

	hash, err := crypto.HashPassword(password)
	if err != nil {
		return nil, err
	}

	userID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	user := &models.User{
		ID:           userID,
		Email:        email,
		PasswordHash: &hash,
		Tenant_ID:    tenantID,
		IsActive:     false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// Email verification token
	emailPlainToken, emailVerificationToken, err :=
		GenerateEmailVerificationToken(userID, s.tokenSecret)
	if err != nil {
		return nil, err
	}

	// Refresh token
	familyID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	plainRefreshToken, refreshToken, err :=
		GenerateRefreshToken(
			user.ID,
			familyID,
			uuid.Nil,
			tenantID,
			clientID,
			s.tokenSecret,
		)
	if err != nil {
		return nil, err
	}

	// User info
	userInfo := &UserInfo{
		UserID:    user.ID,
		Email:     email,
		Username:  username,
		Verified:  false,
		CreatedAt: now,
	}

	// User-created outbox event
	outboxPayload, err := json.Marshal(userInfo)
	if err != nil {
		return nil, err
	}

	userCreatedEventID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	userCreatedEvent := &models.OutboxEvent{
		ID:          userCreatedEventID,
		EventType:   models.UserCreated,
		Payload:     outboxPayload,
		Status:      models.StatusPending,
		NextRetryAt: now,
		CreatedAt:   now,
	}

	// Email verification outbox event
	emailVerificationEventID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	verificationURL := VerifyEmailURLConstructor(s.app_url, emailPlainToken)

	payloadData := models.EmailVerificationRequestPayload{
		VerificationUrl: verificationURL,
		ExpiresAt:       emailVerificationToken.ExpiresAt,
	}

	emailPayload := models.EmailPayloadContext{
		Tenant:      tenantN,
		UserID:      user.ID,
		Email:       email,
		Username:    user.Username,
		EventID:     emailVerificationEventID,
		PayloadData: payloadData,
	}

	emailOutboxPayload, err := json.Marshal(emailPayload)
	if err != nil {
		return nil, err
	}

	emailVerificationEvent := &models.OutboxEvent{
		ID:          emailVerificationEventID,
		EventType:   models.EmailVerificationRequested,
		Payload:     emailOutboxPayload,
		Status:      models.StatusPending,
		NextRetryAt: now,
		CreatedAt:   now,
	}

	return &SignUpDataBundle{
		User:                   user,
		EmailVerificationToken: emailVerificationToken,
		RefreshToken:           refreshToken,
		UserCreatedEvent:       userCreatedEvent,
		EmailVerificationEvent: emailVerificationEvent,
		UserInfoDTO:            userInfo,
		PlainRefreshToken:      plainRefreshToken,
		PlainEmailToken:        emailPlainToken,
	}, nil
}

// signUpTransaction transaction takes the prebuilt models and commits them in a single transaction
func (s *Service) signUpTransaction(
	ctx context.Context,
	user *models.User,
	emailtoken *models.EmailVerificationToken,
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
	if err := s.emailVerifyrepo.CreateTx(ctx, tx, emailtoken); err != nil {
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

// signupResponseBuilder builds the JSON response to be returned to the
// SignupHandler and sent back the requester/client
func (s *Service) signupResponseBuilder(
	user *models.User, userinfo UserInfo, refreshToken string,
) (*SignupResponseRefactor, error) {
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

func (s *Service) SignupService(
	ctx context.Context,
	email, username, password string,
	tenant uuid.UUID,
) (*SignupResponseRefactor, error) {

	cId, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	clientID := signClientID(cId, []byte(s.tokenSecret))
	tenant_model, OK := TenantFromContext(ctx)
	if !OK {
		return nil, errors.New("Couldnt get tenanat")
	}

	tenant_name := tenant_model.TenantName

	sud, err := s.signUpDataBuilder(
		email, username, password,
		clientID, tenant_name, tenant,
	)
	if err != nil {
		return nil, err
	}

	err2 := s.signUpTransaction(
		ctx, sud.User,
		sud.EmailVerificationToken, sud.RefreshToken,
		sud.UserCreatedEvent, sud.EmailVerificationEvent,
	)
	if err2 != nil {
		return nil, err2
	}

	metrics.SignupsTotal.WithLabelValues("success").Inc()
	return s.signupResponseBuilder(sud.User, *sud.UserInfoDTO, sud.PlainRefreshToken)

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
	tenant, ok := TenantFromContext(ctx)
	if !ok || tenant == nil {
		return ErrTenantNotFound
	}
	user, err := s.users.FindByEmail(ctx, email, tenant.ID)
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
			  also IP catching to send the email correctly:
			  	"Hey user we detected a loggin from {IP} at {time}
				 We wanted to confirm it was you,
				 if it wasnt reset your password here {url}
				"
			  also when doing a login it should revoke the previous refresh token,
			  to do the revoke:
			  	- need to determine with session and which family to kill
				- different device shouldn't kill another's device session
*/

func (s *Service) Login(
	ctx context.Context,
	email, password,
	req_ip string,
) (string, string, string, error) {

	tenant, ok := TenantFromContext(ctx)
	if !ok || tenant == nil {
		return "", "", "", ErrTenantNotFound
	}
	loginFailed := func() error {
		metrics.LoginAttemptsTotal.WithLabelValues("failure").Inc()
		return ErrInvalidCredentials
	}

	user, err := s.users.FindByEmail(ctx, email, tenant.ID)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return "", "", "", err
		}
		user = nil
	}

	if user == nil || user.PasswordHash == nil {
		s.rateLimiter.RecordLoginFailure(ctx, req_ip, email, suspiciousLoginNotifyAt) // nts: TODO: consumer policy enters here
		_ = crypto.ComparePassword(dummyPasswordHash, password)
		return "", "", "", loginFailed()
	}

	if err := crypto.ComparePassword(*user.PasswordHash, password); err != nil {
		s.rateLimiter.RecordLoginFailure(ctx, req_ip, email, suspiciousLoginNotifyAt) // nts: TODO: consumer policy enters here
		return "", "", "", loginFailed()
	}

	if user.LockedAt != nil {
		//s.rateLimiter.RecordLoginFailure(ctx, req_ip, email, suspiciousLoginNotifyAt) // nts: TODO: consumer policy enters here
		return "", "", "", ErrUserLockedout
	}

	access, err := GenerateAccessToken(user.ID, user.Email, s.privateKey)
	if err != nil {
		return "", "", "", err
	}

	cId, err := uuid.NewV7()
	if err != nil {
		return "", "", "", err
	}
	clientID := signClientID(cId, []byte(s.tokenSecret))

	familyID, err := uuid.NewV7()
	if err != nil {
		return "", "", "", err
	}
	// nts uuid.nil is used here but further down in the repository layer it is converted to nil and stored that way in the DB
	refreshPlain, refreshModel, err := GenerateRefreshToken(user.ID, familyID, uuid.Nil, user.Tenant_ID, clientID, s.tokenSecret)
	if err != nil {
		return "", "", "", err
	}

	loginEventID, err := uuid.NewV7()
	if err != nil {
		return "", "", "", err
	}

	payload_raw := models.EmailPayloadContext{
		Tenant:   tenant.TenantName,
		UserID:   user.ID,
		Email:    user.Email,
		Username: user.Username,

		EventID: loginEventID,
		IP:      req_ip,
	}

	payload_json, err := json.Marshal(payload_raw)
	if err != nil {
		return "", "", "", err
	}
	LoginOutbox := &models.OutboxEvent{
		ID:          loginEventID,
		EventType:   models.UserLoginSucceeded,
		Payload:     payload_json,
		Status:      models.StatusPending,
		CreatedAt:   time.Now(),
		NextRetryAt: time.Now().Add(1 * time.Minute),
	}

	// search and invalidate previous tokens

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", "", err
	}

	defer func() {
		_ = tx.Rollback()
	}()

	if err := s.outboxrepo.CreateTx(ctx, tx, LoginOutbox); err != nil {
		return "", "", "", err
	}

	if err := s.refreshRepo.CreateTx(ctx, tx, refreshModel); err != nil {
		return "", "", "", err
	}

	if err := tx.Commit(); err != nil {
		return "", "", "", err
	}
	metrics.LoginAttemptsTotal.WithLabelValues("success").Inc()
	return access, refreshPlain, clientID, nil
}

func (s *Service) enqueueNewDeviceEmailTx(
	ctx context.Context,
	tx *sql.Tx,
	user *models.User,
	tenant *models.Tenant,
	dev DeviceInfo,
) error {
	eventID, err := uuid.NewV7()
	if err != nil {
		return err
	}

	now := time.Now()

	payload, err := json.Marshal(models.EmailPayloadContext{
		Tenant:  tenant.TenantName,
		UserID:  user.ID,
		Email:   user.Email,
		EventID: eventID,
		IP:      dev.IP,
		PayloadData: models.NewDeviceLoginPayload{
			UserAgent:        dev.UserAgent,
			IP:               dev.IP,
			LoginAt:          now,
			SecureAccountURL: s.app_url + "/forgot-password", // point at your frontend route
		},
	})
	if err != nil {
		return err
	}

	return s.outboxrepo.CreateTx(ctx, tx, &models.OutboxEvent{
		ID:            eventID,
		AggregateType: "user",
		AggregateID:   user.ID,
		EventType:     models.EmailNewDeviceLogin,
		Status:        models.StatusPending,
		Payload:       payload,
		CreatedAt:     now,
		NextRetryAt:   now,
	})
}

func (s *Service) rotateHelper(ctx context.Context, refreshToken string) (string, *models.RefreshToken, error) {
	tenant, ok := TenantFromContext(ctx)
	if !ok || tenant == nil {
		return "", nil, ErrTenantNotFound
	}

	hash := crypto.HashToken(refreshToken, s.tokenSecret)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	old, err := s.refreshRepo.FindbyHash(ctx, tx, hash, tenant.ID)
	if err != nil {
		return "", nil, ErrInvalidToken
	}

	if old.ExpiresAt.Before(time.Now()) {
		return "", nil, ErrInvalidToken
	}

	if old.RevokedAt != nil {
		err = s.refreshRepo.RevokeAllForFamily(ctx, tx, old.FamilyID, tenant.ID)
		if err != nil {
			return "", nil, err
		}
		err = tx.Commit()
		if err != nil {
			return "", nil, err
		}

		metrics.RefreshReuseDetectedTotal.Inc()
		return "", nil, ErrRefreshReuse
	}

	if err := s.refreshRepo.Revoke(ctx, tx, old.ID, tenant.ID); err != nil {
		return "", nil, err
	}

	plain, model, err := GenerateRefreshToken(
		old.UserID,
		old.FamilyID,
		old.ID,
		tenant.ID,
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

	tenant, ok := TenantFromContext(ctx)
	if !ok || tenant == nil {
		return ErrTenantNotFound
	}

	hash := crypto.HashToken(refreshToken, s.tokenSecret)

	rt, err := s.refreshRepo.FindValidByHash(ctx, hash, tenant.ID)
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

	if err := s.refreshRepo.Revoke(ctx, tx, rt.ID, tenant.ID); err != nil {
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (s *Service) RevokeAll(ctx context.Context, userID uuid.UUID) error {
	tenant, ok := TenantFromContext(ctx)
	if !ok || tenant == nil {
		return ErrTenantNotFound
	}
	return s.refreshRepo.RevokeAllForUser(ctx, userID, tenant.ID)
}

/*
requires a JWT session and a user

implement IP picking and email send
*/

/*
Change password:

	Used when user wants to change its password manualy
	User knows its password and account isnt stolen
*/
func (s *Service) ChangePassword(ctx context.Context, req ChangePasswordRequest, ip string) error {

	tenant, ok := TenantFromContext(ctx)
	if !ok || tenant == nil {
		return ErrTenantNotFound
	}

	/* Add here JWT functionality */

	user, err := s.users.FindByEmail(ctx, req.Email, tenant.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
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

	err = s.users.ChangePassword(ctx, tx, user.ID, hashedpassword)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidCredentials
		}
		return err
	}

	outboxEvent_createID, err := uuid.NewV7()
	if err != nil {
		return err
	}

	WrapperPayload := models.EmailPayloadContext{
		Tenant:   tenant.TenantName,
		UserID:   user.ID,
		Email:    user.Email,
		Username: user.Username,

		IP:      ip,
		EventID: outboxEvent_createID,
	}

	outboxPayload, err := json.Marshal(WrapperPayload)
	if err != nil {
		return err
	}

	now := time.Now()

	newoutboxevent := &models.OutboxEvent{
		ID:          outboxEvent_createID,
		EventType:   models.EmailPasswordResetRequested,
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
		return err
	}
	return nil

}

/*
nts: TODO: rn it creates a new token and done, instead it should create and then invalidate the previous one
*/

/*
When a user forgets their password and wants to change it voluntarily, sends an email to the user's email
with a link to change it
*/
func (s *Service) RequestResetPassword(ctx context.Context, email string, ip string) error {
	tenant, ok := TenantFromContext(ctx)
	if !ok || tenant == nil {
		return ErrTenantNotFound
	}
	user, err := s.users.FindByEmail(ctx, email, tenant.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}

	plainToken, resetModel, err := GeneratePasswordResetToken(user.ID, tenant.ID, s.tokenSecret)

	if err != nil {
		return err
	}

	resetLink := s.app_url + "/auth/reset-password?t=" + plainToken
	println("resetlink: ", resetLink)

	outboxEvent_ID, err := uuid.NewV7()
	if err != nil {
		return err
	}

	PasswordRRPayload := models.PasswordResetRequestedPayload{
		ResetLink: resetLink,
	}

	PayloadRaw := models.EmailPayloadContext{
		Tenant: tenant.TenantName,
		UserID: user.ID,
		Email:  user.Email,

		EventID:     outboxEvent_ID,
		IP:          ip,
		PayloadData: PasswordRRPayload,
	}

	payload, err := json.Marshal(PayloadRaw)
	if err != nil {
		return err
	}

	now := time.Now()

	newoutbox := &models.OutboxEvent{
		ID:          outboxEvent_ID,
		EventType:   models.EmailPasswordResetRequested,
		Status:      models.StatusPending,
		Payload:     payload,
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

	if err := s.refreshRepo.CreateResetTokenTx(ctx, tx, *resetModel); err != nil {
		return err
	}

	if err := s.outboxrepo.CreateTx(ctx, tx, newoutbox); err != nil {
		return err
	}

	if err := s.refreshRepo.RevokePreviousResetTokens(ctx, tx, tenant.ID, user.ID); err != nil {
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

/*
Recieves the token from the request password reset endpoint and allows the user to enter a new password
*/
func (s *Service) ResetPassword(ctx context.Context, rawToken string, newPassword string, ip string) error {
	tenant, ok := TenantFromContext(ctx)
	if !ok || tenant == nil {
		return ErrTenantNotFound
	}

	hash := crypto.HashToken(rawToken, s.tokenSecret)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	resetToken, err := s.refreshRepo.FindValidResetTokenTx(ctx, tx, hash, tenant.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			println("ping")
			return ErrInvalidToken
		}
		return err
	}

	hashedPassword, err := crypto.HashPassword(newPassword)
	if err != nil {
		return err
	}

	if err := s.users.ChangePassword(ctx, tx, resetToken.UserID, hashedPassword); err != nil {
		return err
	}

	if err := s.refreshRepo.MarkResetTokenUsedTx(ctx, tx, resetToken.ID); err != nil {
		return err
	}

	if err := s.refreshRepo.RevokeAllForUser(ctx, resetToken.UserID, tenant.ID); err != nil {
		return err
	}

	user, err := s.users.FindByID(ctx, resetToken.UserID)
	if err != nil {
		return err
	}

	outboxEventID, err := uuid.NewV7()
	if err != nil {
		return err
	}

	rawpayload := models.EmailPayloadContext{
		Tenant:   tenant.TenantName,
		UserID:   user.ID,
		Email:    user.Email,
		Username: user.Username,

		EventID: outboxEventID,
		IP:      ip,
	}

	payload, err := json.Marshal(rawpayload)
	if err != nil {
		return err
	}

	now := time.Now()
	confirmEvent := &models.OutboxEvent{
		ID:          outboxEventID,
		EventType:   models.UserPasswordResetSucceeded,
		Status:      models.StatusPending,
		Payload:     payload,
		CreatedAt:   now,
		NextRetryAt: now.Add(time.Minute * 5),
	}

	if err := s.outboxrepo.CreateTx(ctx, tx, confirmEvent); err != nil {
		return err
	}

	return tx.Commit()
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
