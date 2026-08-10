package users

import (
	"AuthAPI/main/internal/models"
	"AuthAPI/main/internal/tests"
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	testDB            *sql.DB
	dockerUnavailable string
)

func TestMain(m *testing.M) {
	var teardown func()
	testDB, dockerUnavailable, teardown = tests.SetupTestDB()
	defer teardown()
	os.Exit(m.Run())
}

func newTestUser() *models.User {
	now := time.Now().UTC().Truncate(time.Microsecond)

	username := "test-" + uuid.NewString()
	passwordHash := "hashed-password"

	return &models.User{
		ID:            uuid.New(),
		Email:         "test-" + uuid.NewString() + "@example.com",
		Username:      &username,
		PasswordHash:  &passwordHash,
		EmailVerified: false,
		IsActive:      false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func newTestRepository(t *testing.T) Repository {
	t.Helper()

	db := tests.RequirePostgres(t, testDB, dockerUnavailable)

	return NewPostgresRepository(db)
}

func cleanupUser(t *testing.T, userID uuid.UUID) {
	t.Helper()

	_, err := testDB.ExecContext(
		context.Background(),
		`DELETE FROM users WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		t.Fatalf("failed to cleanup user %s: %v", userID, err)
	}
}

func stringPtr(s string) *string {
	return &s
}

func assertUserEqual(t *testing.T, got, want *models.User) {
	t.Helper()

	if got == nil {
		t.Fatal("got user = nil, want non-nil")
	}

	if got.ID != want.ID {
		t.Errorf("ID = %v, want %v", got.ID, want.ID)
	}

	if got.Email != want.Email {
		t.Errorf("Email = %q, want %q", got.Email, want.Email)
	}

	if !equalStringPtr(got.Username, want.Username) {
		t.Errorf("Username = %v, want %v", got.Username, want.Username)
	}

	if !equalStringPtr(got.PasswordHash, want.PasswordHash) {
		t.Errorf(
			"PasswordHash = %v, want %v",
			got.PasswordHash,
			want.PasswordHash,
		)
	}

	if got.EmailVerified != want.EmailVerified {
		t.Errorf(
			"EmailVerified = %v, want %v",
			got.EmailVerified,
			want.EmailVerified,
		)
	}

	if got.IsActive != want.IsActive {
		t.Errorf(
			"IsActive = %v, want %v",
			got.IsActive,
			want.IsActive,
		)
	}

	if !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf(
			"CreatedAt = %v, want %v",
			got.CreatedAt,
			want.CreatedAt,
		)
	}

	if !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Errorf(
			"UpdatedAt = %v, want %v",
			got.UpdatedAt,
			want.UpdatedAt,
		)
	}
}

func equalStringPtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}

	return *a == *b
}

// Create
func TestPostgresRepository_Create(t *testing.T) {
	repo := newTestRepository(t)
	user := newTestUser()

	t.Cleanup(func() {
		cleanupUser(t, user.ID)
	})

	ctx := context.Background()

	err := repo.Create(ctx, user)
	if err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	got, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindByID() returned unexpected error: %v", err)
	}

	assertUserEqual(t, got, user)
}

func TestPostgresRepository_Create_NullableFields(t *testing.T) {
	repo := newTestRepository(t)
	user := newTestUser()

	user.Username = nil
	user.PasswordHash = nil

	t.Cleanup(func() {
		cleanupUser(t, user.ID)
	})

	ctx := context.Background()

	err := repo.Create(ctx, user)
	if err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	got, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindByID() returned unexpected error: %v", err)
	}

	assertUserEqual(t, got, user)

	if got.Username != nil {
		t.Errorf("Username = %v, want nil", got.Username)
	}

	if got.PasswordHash != nil {
		t.Errorf("PasswordHash = %v, want nil", got.PasswordHash)
	}
}

func TestPostgresRepository_Create_DuplicateEmail(t *testing.T) {
	repo := newTestRepository(t)

	first := newTestUser()
	second := newTestUser()
	second.Email = first.Email

	t.Cleanup(func() {
		cleanupUser(t, first.ID)
		cleanupUser(t, second.ID)
	})

	ctx := context.Background()

	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("Create(first) returned unexpected error: %v", err)
	}

	err := repo.Create(ctx, second)
	if err == nil {
		t.Fatal("Create(second) returned nil error, want duplicate email error")
	}
}

func TestPostgresRepository_Create_DuplicateUsername(t *testing.T) {
	repo := newTestRepository(t)

	first := newTestUser()
	second := newTestUser()

	second.Username = first.Username

	t.Cleanup(func() {
		cleanupUser(t, first.ID)
		cleanupUser(t, second.ID)
	})

	ctx := context.Background()

	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("Create(first) returned unexpected error: %v", err)
	}

	err := repo.Create(ctx, second)
	if err == nil {
		t.Fatal("Create(second) returned nil error, want duplicate username error")
	}
}

func TestPostgresRepository_Create_NullUsernameAllowsMultipleUsers(t *testing.T) {
	repo := newTestRepository(t)

	first := newTestUser()
	second := newTestUser()

	first.Username = nil
	second.Username = nil

	t.Cleanup(func() {
		cleanupUser(t, first.ID)
		cleanupUser(t, second.ID)
	})

	ctx := context.Background()

	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("Create(first) returned unexpected error: %v", err)
	}

	if err := repo.Create(ctx, second); err != nil {
		t.Fatalf("Create(second) returned unexpected error: %v", err)
	}
}

// CreateTx
func TestPostgresRepository_CreateTx_Commit(t *testing.T) {
	repo := newTestRepository(t)
	user := newTestUser()

	t.Cleanup(func() {
		cleanupUser(t, user.ID)
	})

	ctx := context.Background()

	tx, err := testDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx() returned unexpected error: %v", err)
	}

	err = repo.CreateTx(ctx, tx, user)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("CreateTx() returned unexpected error: %v", err)
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit() returned unexpected error: %v", err)
	}

	got, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindByID() returned unexpected error: %v", err)
	}

	assertUserEqual(t, got, user)
}

func TestPostgresRepository_CreateTx_Rollback(t *testing.T) {
	repo := newTestRepository(t)
	user := newTestUser()

	ctx := context.Background()

	tx, err := testDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx() returned unexpected error: %v", err)
	}

	err = repo.CreateTx(ctx, tx, user)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("CreateTx() returned unexpected error: %v", err)
	}

	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback() returned unexpected error: %v", err)
	}

	_, err = repo.FindByID(ctx, user.ID)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf(
			"FindByID() error = %v, want %v",
			err,
			sql.ErrNoRows,
		)
	}
}

// FindByEmail
func TestPostgresRepository_FindByEmail(t *testing.T) {
	repo := newTestRepository(t)
	user := newTestUser()

	t.Cleanup(func() {
		cleanupUser(t, user.ID)
	})

	ctx := context.Background()

	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	got, err := repo.FindByEmail(ctx, user.Email)
	if err != nil {
		t.Fatalf("FindByEmail() returned unexpected error: %v", err)
	}

	assertUserEqual(t, got, user)
}

func TestPostgresRepository_FindByEmail_NotFound(t *testing.T) {
	repo := newTestRepository(t)

	ctx := context.Background()

	got, err := repo.FindByEmail(
		ctx,
		"does-not-exist-"+uuid.NewString()+"@example.com",
	)

	if got != nil {
		t.Fatalf("FindByEmail() returned user = %+v, want nil", got)
	}

	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf(
			"FindByEmail() error = %v, want %v",
			err,
			sql.ErrNoRows,
		)
	}
}

func TestPostgresRepository_FindByEmail_NullableFields(t *testing.T) {
	repo := newTestRepository(t)
	user := newTestUser()

	user.Username = nil
	user.PasswordHash = nil

	t.Cleanup(func() {
		cleanupUser(t, user.ID)
	})

	ctx := context.Background()

	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	got, err := repo.FindByEmail(ctx, user.Email)
	if err != nil {
		t.Fatalf("FindByEmail() returned unexpected error: %v", err)
	}

	assertUserEqual(t, got, user)
}

// FindByID

func TestPostgresRepository_FindByID(t *testing.T) {
	repo := newTestRepository(t)
	user := newTestUser()

	t.Cleanup(func() {
		cleanupUser(t, user.ID)
	})

	ctx := context.Background()

	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	got, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindByID() returned unexpected error: %v", err)
	}

	assertUserEqual(t, got, user)
}

func TestPostgresRepository_FindByID_NotFound(t *testing.T) {
	repo := newTestRepository(t)

	ctx := context.Background()

	got, err := repo.FindByID(ctx, uuid.New())

	if got != nil {
		t.Fatalf("FindByID() returned user = %+v, want nil", got)
	}

	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf(
			"FindByID() error = %v, want %v",
			err,
			sql.ErrNoRows,
		)
	}
}

func TestPostgresRepository_FindByID_NullableFields(t *testing.T) {
	repo := newTestRepository(t)
	user := newTestUser()

	user.Username = nil
	user.PasswordHash = nil

	t.Cleanup(func() {
		cleanupUser(t, user.ID)
	})

	ctx := context.Background()

	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	got, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindByID() returned unexpected error: %v", err)
	}

	if got.Username != nil {
		t.Errorf("Username = %v, want nil", got.Username)
	}

	if got.PasswordHash != nil {
		t.Errorf("PasswordHash = %v, want nil", got.PasswordHash)
	}
}

// ActivateUser
func TestPostgresRepository_ActivateUser(t *testing.T) {
	repo := newTestRepository(t)
	user := newTestUser()

	user.IsActive = false
	user.EmailVerified = false

	t.Cleanup(func() {
		cleanupUser(t, user.ID)
	})

	ctx := context.Background()

	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	before, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindByID(before) returned unexpected error: %v", err)
	}

	if err := repo.ActivateUser(ctx, user.ID); err != nil {
		t.Fatalf("ActivateUser() returned unexpected error: %v", err)
	}

	after, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindByID(after) returned unexpected error: %v", err)
	}

	if !after.IsActive {
		t.Error("IsActive = false, want true")
	}

	if !after.EmailVerified {
		t.Error("EmailVerified = false, want true")
	}

	if !after.UpdatedAt.After(before.UpdatedAt) {
		t.Errorf(
			"UpdatedAt = %v, want after %v",
			after.UpdatedAt,
			before.UpdatedAt,
		)
	}
}

func TestPostgresRepository_ActivateUser_DoesNotChangeOtherFields(t *testing.T) {
	repo := newTestRepository(t)
	user := newTestUser()

	user.IsActive = false
	user.EmailVerified = false

	t.Cleanup(func() {
		cleanupUser(t, user.ID)
	})

	ctx := context.Background()

	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	before, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindByID(before) returned unexpected error: %v", err)
	}

	if err := repo.ActivateUser(ctx, user.ID); err != nil {
		t.Fatalf("ActivateUser() returned unexpected error: %v", err)
	}

	after, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindByID(after) returned unexpected error: %v", err)
	}

	if after.ID != before.ID {
		t.Errorf("ID changed: before=%v after=%v", before.ID, after.ID)
	}

	if after.Email != before.Email {
		t.Errorf(
			"Email changed: before=%q after=%q",
			before.Email,
			after.Email,
		)
	}

	if !equalStringPtr(after.Username, before.Username) {
		t.Errorf(
			"Username changed: before=%v after=%v",
			before.Username,
			after.Username,
		)
	}

	if !equalStringPtr(after.PasswordHash, before.PasswordHash) {
		t.Errorf(
			"PasswordHash changed: before=%v after=%v",
			before.PasswordHash,
			after.PasswordHash,
		)
	}

	if !after.IsActive {
		t.Error("IsActive = false, want true")
	}

	if !after.EmailVerified {
		t.Error("EmailVerified = false, want true")
	}

	if !after.CreatedAt.Equal(before.CreatedAt) {
		t.Errorf(
			"CreatedAt changed: before=%v after=%v",
			before.CreatedAt,
			after.CreatedAt,
		)
	}
}

func TestPostgresRepository_ActivateUser_AlreadyActive(t *testing.T) {
	repo := newTestRepository(t)
	user := newTestUser()

	user.IsActive = true
	user.EmailVerified = true

	t.Cleanup(func() {
		cleanupUser(t, user.ID)
	})

	ctx := context.Background()

	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	if err := repo.ActivateUser(ctx, user.ID); err != nil {
		t.Fatalf("ActivateUser() returned unexpected error: %v", err)
	}

	got, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindByID() returned unexpected error: %v", err)
	}

	if !got.IsActive {
		t.Error("IsActive = false, want true")
	}

	if !got.EmailVerified {
		t.Error("EmailVerified = false, want true")
	}
}

func TestPostgresRepository_ActivateUser_NotFound(t *testing.T) {
	repo := newTestRepository(t)

	ctx := context.Background()

	err := repo.ActivateUser(ctx, uuid.New())

	// nts: Current implementation does not check RowsAffected(), so PostgreSQL returns nil even when no user matches the UPDATE.
	if err != nil {
		t.Fatalf(
			"ActivateUser() returned unexpected error: %v",
			err,
		)
	}
}
