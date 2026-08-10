package refresh

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"AuthAPI/main/internal/models"
	"AuthAPI/main/internal/tests"

	"github.com/google/uuid"
)

var (
	pgTestDB            *sql.DB
	pgDockerUnavailable string
)

func TestMain(m *testing.M) {
	var teardown func()
	pgTestDB, pgDockerUnavailable, teardown = tests.SetupTestDB()
	defer teardown()
	os.Exit(m.Run())
}

func requirePostgres(t *testing.T) *sql.DB {
	return tests.RequirePostgres(t, pgTestDB, pgDockerUnavailable)
}

func insertTestUser(t *testing.T, ctx context.Context, tx *sql.Tx) uuid.UUID {
	t.Helper()

	userID := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)

	_, err := tx.ExecContext(ctx, `
		INSERT INTO users (user_id, email, email_verified, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, userID, "user-"+userID.String()+"@example.com", false, true, now, now)
	if err != nil {
		t.Fatalf("failed to insert test user fixture: %v", err)
	}

	return userID
}

func newRefreshToken(t *testing.T, ctx context.Context, tx *sql.Tx) *models.RefreshToken {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond) // TIMESTAMPTZ precision

	return &models.RefreshToken{
		ID:        uuid.New(),
		UserID:    insertTestUser(t, ctx, tx),
		TokenHash: "hash-" + uuid.NewString(),
		ClientID:  "client-" + uuid.NewString(),
		FamilyID:  uuid.New(),
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}
}

func withRefreshTx(t *testing.T, fn func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo)) {
	t.Helper()
	db := requirePostgres(t)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("failed to begin tx: %v", err)
	}
	t.Cleanup(func() {
		_ = tx.Rollback()
	})

	repo := &refreshPostgresRepo{db: tx}
	fn(ctx, tx, repo)
}

// ---------- Create ----------

func TestRefreshPostgresRepo_Create(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		token := newRefreshToken(t, ctx, tx)

		if err := repo.Create(ctx, token); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		var got models.RefreshToken
		var parent sql.NullString

		err := tx.QueryRowContext(ctx, `
			SELECT token_id, user_id, token_hash, client_id,
			       family_id, ptoken_id, expires_at, created_at
			FROM refresh_tokens
			WHERE token_id = $1
		`, token.ID).Scan(
			&got.ID, &got.UserID, &got.TokenHash, &got.ClientID,
			&got.FamilyID, &parent, &got.ExpiresAt, &got.CreatedAt,
		)
		if err != nil {
			t.Fatalf("failed to query created token: %v", err)
		}

		if got.ID != token.ID {
			t.Errorf("ID = %v, want %v", got.ID, token.ID)
		}
		if got.UserID != token.UserID {
			t.Errorf("UserID = %v, want %v", got.UserID, token.UserID)
		}
		if got.TokenHash != token.TokenHash {
			t.Errorf("TokenHash = %q, want %q", got.TokenHash, token.TokenHash)
		}
		if got.ClientID != token.ClientID {
			t.Errorf("ClientID = %q, want %q", got.ClientID, token.ClientID)
		}
		if got.FamilyID != token.FamilyID {
			t.Errorf("FamilyID = %v, want %v", got.FamilyID, token.FamilyID)
		}
		if parent.Valid {
			t.Errorf("ptoken_id = %q, want NULL", parent.String)
		}
	})
}

func TestRefreshPostgresRepo_Create_WithParentToken(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		parentID := uuid.New()

		token := newRefreshToken(t, ctx, tx)
		token.ParentToken = parentID

		if err := repo.Create(ctx, token); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		var parent sql.NullString
		err := tx.QueryRowContext(ctx, `
			SELECT ptoken_id FROM refresh_tokens WHERE token_id = $1
		`, token.ID).Scan(&parent)
		if err != nil {
			t.Fatalf("failed to query created token: %v", err)
		}

		if !parent.Valid {
			t.Fatal("ptoken_id is NULL, want parent token ID")
		}
		if parent.String != parentID.String() {
			t.Errorf("ptoken_id = %q, want %q", parent.String, parentID)
		}
	})
}

func TestRefreshPostgresRepo_Create_ContextCanceled(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		err := repo.Create(cctx, newRefreshToken(t, ctx, tx))
		if err == nil {
			t.Fatal("Create() error = nil, want context cancellation error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Create() error = %v, want context.Canceled", err)
		}
	})
}

// ---------- CreateTx ----------

func TestRefreshPostgresRepo_CreateTx(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		token := newRefreshToken(t, ctx, tx)

		if err := repo.CreateTx(ctx, tx, token); err != nil {
			t.Fatalf("CreateTx() error = %v", err)
		}

		var count int
		err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM refresh_tokens WHERE token_id = $1
		`, token.ID).Scan(&count)
		if err != nil {
			t.Fatalf("failed to query token: %v", err)
		}
		if count != 1 {
			t.Fatalf("token count = %d, want 1", count)
		}
	})
}

func TestRefreshPostgresRepo_CreateTx_RollbackDiscardsInsert(t *testing.T) {
	// nested SAVEPOINT instead of rolling back the whole shared tx, clean up normally afterwards.
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		if _, err := tx.ExecContext(ctx, "SAVEPOINT create_tx_test"); err != nil {
			t.Fatalf("failed to create savepoint: %v", err)
		}

		token := newRefreshToken(t, ctx, tx)
		if err := repo.CreateTx(ctx, tx, token); err != nil {
			t.Fatalf("CreateTx() error = %v", err)
		}

		if _, err := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT create_tx_test"); err != nil {
			t.Fatalf("failed to roll back to savepoint: %v", err)
		}

		var count int
		err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM refresh_tokens WHERE token_id = $1
		`, token.ID).Scan(&count)
		if err != nil {
			t.Fatalf("failed to query token: %v", err)
		}
		if count != 0 {
			t.Fatalf("token count = %d after rollback, want 0", count)
		}
	})
}

func TestRefreshPostgresRepo_CreateTx_ContextCanceled(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		err := repo.CreateTx(cctx, tx, newRefreshToken(t, ctx, tx))
		if err == nil {
			t.Fatal("CreateTx() error = nil, want context cancellation error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("CreateTx() error = %v, want context.Canceled", err)
		}
	})
}

// ---------- FindbyHash ----------

func TestRefreshPostgresRepo_FindbyHash(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		token := newRefreshToken(t, ctx, tx)
		token.ParentToken = uuid.New()

		if err := repo.Create(ctx, token); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		got, err := repo.FindbyHash(ctx, tx, token.TokenHash)
		if err != nil {
			t.Fatalf("FindbyHash() error = %v", err)
		}
		if got == nil {
			t.Fatal("FindbyHash() returned nil token")
		}

		if got.ID != token.ID {
			t.Errorf("ID = %v, want %v", got.ID, token.ID)
		}
		if got.UserID != token.UserID {
			t.Errorf("UserID = %v, want %v", got.UserID, token.UserID)
		}
		if got.TokenHash != token.TokenHash {
			t.Errorf("TokenHash = %q, want %q", got.TokenHash, token.TokenHash)
		}
		if got.ClientID != token.ClientID {
			t.Errorf("ClientID = %q, want %q", got.ClientID, token.ClientID)
		}
		if got.FamilyID != token.FamilyID {
			t.Errorf("FamilyID = %v, want %v", got.FamilyID, token.FamilyID)
		}
		if got.ParentToken != token.ParentToken {
			t.Errorf("ParentToken = %v, want %v", got.ParentToken, token.ParentToken)
		}
		if !got.ExpiresAt.Equal(token.ExpiresAt) {
			t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, token.ExpiresAt)
		}
		if !got.CreatedAt.Equal(token.CreatedAt) {
			t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, token.CreatedAt)
		}
		if got.RevokedAt != nil {
			t.Errorf("RevokedAt = %v, want nil", got.RevokedAt)
		}
	})
}

func TestRefreshPostgresRepo_FindbyHash_WithoutParent(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		token := newRefreshToken(t, ctx, tx)

		if err := repo.Create(ctx, token); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		got, err := repo.FindbyHash(ctx, tx, token.TokenHash)
		if err != nil {
			t.Fatalf("FindbyHash() error = %v", err)
		}
		if got.ParentToken != uuid.Nil {
			t.Errorf("ParentToken = %v, want uuid.Nil", got.ParentToken)
		}
	})
}

func TestRefreshPostgresRepo_FindbyHash_NotFound(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		_, err := repo.FindbyHash(ctx, tx, "does-not-exist-"+uuid.NewString())
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("FindbyHash() error = %v, want %v", err, sql.ErrNoRows)
		}
	})
}

func TestRefreshPostgresRepo_FindbyHash_InTransaction(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		token := newRefreshToken(t, ctx, tx)

		if err := repo.CreateTx(ctx, tx, token); err != nil {
			t.Fatalf("CreateTx() error = %v", err)
		}

		got, err := repo.FindbyHash(ctx, tx, token.TokenHash)
		if err != nil {
			t.Fatalf("FindbyHash() error = %v", err)
		}
		if got.ID != token.ID {
			t.Errorf("ID = %v, want %v", got.ID, token.ID)
		}
	})
}

func TestRefreshPostgresRepo_FindbyHash_ContextCanceled(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		_, err := repo.FindbyHash(cctx, tx, "anything")
		if err == nil {
			t.Fatal("FindbyHash() error = nil, want context cancellation error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("FindbyHash() error = %v, want context.Canceled", err)
		}
	})
}

// ---------- FindValidByHash ----------

func TestRefreshPostgresRepo_FindValidByHash_ValidToken(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		token := newRefreshToken(t, ctx, tx)

		if err := repo.Create(ctx, token); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		got, err := repo.FindValidByHash(ctx, token.TokenHash)
		if err != nil {
			t.Fatalf("FindValidByHash() error = %v", err)
		}
		if got.ID != token.ID {
			t.Errorf("ID = %v, want %v", got.ID, token.ID)
		}
		if got.TokenHash != token.TokenHash {
			t.Errorf("TokenHash = %q, want %q", got.TokenHash, token.TokenHash)
		}
	})
}

func TestRefreshPostgresRepo_FindValidByHash_RevokedToken(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		token := newRefreshToken(t, ctx, tx)

		if err := repo.Create(ctx, token); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		_, err := tx.ExecContext(ctx, `
			UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE token_id = $1
		`, token.ID)
		if err != nil {
			t.Fatalf("failed to revoke token: %v", err)
		}

		_, err = repo.FindValidByHash(ctx, token.TokenHash)
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("FindValidByHash() error = %v, want %v", err, sql.ErrNoRows)
		}
	})
}

func TestRefreshPostgresRepo_FindValidByHash_ExpiredToken(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		token := newRefreshToken(t, ctx, tx)
		token.ExpiresAt = time.Now().UTC().Add(-time.Hour)

		if err := repo.Create(ctx, token); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		_, err := repo.FindValidByHash(ctx, token.TokenHash)
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("FindValidByHash() error = %v, want %v", err, sql.ErrNoRows)
		}
	})
}

func TestRefreshPostgresRepo_FindValidByHash_NotFound(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		_, err := repo.FindValidByHash(ctx, "does-not-exist-"+uuid.NewString())
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("FindValidByHash() error = %v, want %v", err, sql.ErrNoRows)
		}
	})
}

func TestRefreshPostgresRepo_FindValidByHash_ContextCanceled(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		_, err := repo.FindValidByHash(cctx, "anything")
		if err == nil {
			t.Fatal("FindValidByHash() error = nil, want context cancellation error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("FindValidByHash() error = %v, want context.Canceled", err)
		}
	})
}

// ---------- Revoke ----------

func TestRefreshPostgresRepo_Revoke(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		token := newRefreshToken(t, ctx, tx)
		if err := repo.Create(ctx, token); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		if err := repo.Revoke(ctx, tx, token.ID); err != nil {
			t.Fatalf("Revoke() error = %v", err)
		}

		var revokedAt sql.NullTime
		err := tx.QueryRowContext(ctx, `
			SELECT revoked_at FROM refresh_tokens WHERE token_id = $1
		`, token.ID).Scan(&revokedAt)
		if err != nil {
			t.Fatalf("failed to query revoked token: %v", err)
		}

		if !revokedAt.Valid {
			t.Fatal("revoked_at is NULL, want timestamp")
		}
		// Avoid wall-clock before/after window (can break if Revoke's time.Now() and the test's clock disagree on timezone/precision);
		if !revokedAt.Time.After(token.CreatedAt) {
			t.Errorf("revoked_at = %v, want after created_at %v", revokedAt.Time, token.CreatedAt)
		}
	})
}

func TestRefreshPostgresRepo_Revoke_NonExistentToken(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		if err := repo.Revoke(ctx, tx, uuid.New()); err != nil {
			t.Fatalf("Revoke() error = %v, want nil", err)
		}
	})
}

func TestRefreshPostgresRepo_Revoke_ContextCanceled(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		err := repo.Revoke(cctx, tx, uuid.New())
		if err == nil {
			t.Fatal("Revoke() error = nil, want context cancellation error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Revoke() error = %v, want context.Canceled", err)
		}
	})
}

// ---------- RevokeAllForUser ----------

func TestRefreshPostgresRepo_RevokeAllForUser(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		userID := insertTestUser(t, ctx, tx)

		token1 := newRefreshToken(t, ctx, tx)
		token1.UserID = userID
		token2 := newRefreshToken(t, ctx, tx)
		token2.UserID = userID
		otherUserToken := newRefreshToken(t, ctx, tx)

		for _, tok := range []*models.RefreshToken{token1, token2, otherUserToken} {
			if err := repo.Create(ctx, tok); err != nil {
				t.Fatalf("Create() error = %v", err)
			}
		}

		if err := repo.RevokeAllForUser(ctx, userID); err != nil {
			t.Fatalf("RevokeAllForUser() error = %v", err)
		}

		var revokedCount int
		err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM refresh_tokens
			WHERE user_id = $1 AND revoked_at IS NOT NULL
		`, userID).Scan(&revokedCount)
		if err != nil {
			t.Fatalf("failed to count revoked tokens: %v", err)
		}
		if revokedCount != 2 {
			t.Errorf("revoked count = %d, want 2", revokedCount)
		}

		var otherUserRevoked bool
		err = tx.QueryRowContext(ctx, `
			SELECT revoked_at IS NOT NULL FROM refresh_tokens WHERE token_id = $1
		`, otherUserToken.ID).Scan(&otherUserRevoked)
		if err != nil {
			t.Fatalf("failed to query other user's token: %v", err)
		}
		if otherUserRevoked {
			t.Error("RevokeAllForUser() revoked another user's token")
		}
	})
}

func TestRefreshPostgresRepo_RevokeAllForUser_DoesNotChangeAlreadyRevoked(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		userID := insertTestUser(t, ctx, tx)
		token := newRefreshToken(t, ctx, tx)
		token.UserID = userID

		if err := repo.Create(ctx, token); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		originalRevokedAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
		_, err := tx.ExecContext(ctx, `
			UPDATE refresh_tokens SET revoked_at = $1 WHERE token_id = $2
		`, originalRevokedAt, token.ID)
		if err != nil {
			t.Fatalf("failed to revoke token: %v", err)
		}

		if err := repo.RevokeAllForUser(ctx, userID); err != nil {
			t.Fatalf("RevokeAllForUser() error = %v", err)
		}

		var revokedAt time.Time
		err = tx.QueryRowContext(ctx, `
			SELECT revoked_at FROM refresh_tokens WHERE token_id = $1
		`, token.ID).Scan(&revokedAt)
		if err != nil {
			t.Fatalf("failed to query revoked token: %v", err)
		}
		if !revokedAt.Equal(originalRevokedAt) {
			t.Errorf("revoked_at = %v, want unchanged value %v", revokedAt, originalRevokedAt)
		}
	})
}

func TestRefreshPostgresRepo_RevokeAllForUser_ContextCanceled(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		err := repo.RevokeAllForUser(cctx, uuid.New())
		if err == nil {
			t.Fatal("RevokeAllForUser() error = nil, want context cancellation error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("RevokeAllForUser() error = %v, want context.Canceled", err)
		}
	})
}

// ---------- RevokeAllForFamily ----------

func TestRefreshPostgresRepo_RevokeAllForFamily(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		familyID := uuid.New()

		token1 := newRefreshToken(t, ctx, tx)
		token1.FamilyID = familyID
		token2 := newRefreshToken(t, ctx, tx)
		token2.FamilyID = familyID
		otherFamilyToken := newRefreshToken(t, ctx, tx)

		for _, tok := range []*models.RefreshToken{token1, token2, otherFamilyToken} {
			if err := repo.Create(ctx, tok); err != nil {
				t.Fatalf("Create() error = %v", err)
			}
		}

		if err := repo.RevokeAllForFamily(ctx, tx, familyID); err != nil {
			t.Fatalf("RevokeAllForFamily() error = %v", err)
		}

		var revokedCount int
		err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM refresh_tokens
			WHERE family_id = $1 AND revoked_at IS NOT NULL
		`, familyID).Scan(&revokedCount)
		if err != nil {
			t.Fatalf("failed to count revoked tokens: %v", err)
		}
		if revokedCount != 2 {
			t.Errorf("revoked count = %d, want 2", revokedCount)
		}

		var otherFamilyRevoked bool
		err = tx.QueryRowContext(ctx, `
			SELECT revoked_at IS NOT NULL FROM refresh_tokens WHERE token_id = $1
		`, otherFamilyToken.ID).Scan(&otherFamilyRevoked)
		if err != nil {
			t.Fatalf("failed to query other family's token: %v", err)
		}
		if otherFamilyRevoked {
			t.Error("RevokeAllForFamily() revoked a token from another family")
		}
	})
}

func TestRefreshPostgresRepo_RevokeAllForFamily_DoesNotChangeAlreadyRevoked(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		familyID := uuid.New()
		token := newRefreshToken(t, ctx, tx)
		token.FamilyID = familyID

		if err := repo.Create(ctx, token); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		originalRevokedAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
		_, err := tx.ExecContext(ctx, `
			UPDATE refresh_tokens SET revoked_at = $1 WHERE token_id = $2
		`, originalRevokedAt, token.ID)
		if err != nil {
			t.Fatalf("failed to revoke token: %v", err)
		}

		if err := repo.RevokeAllForFamily(ctx, tx, familyID); err != nil {
			t.Fatalf("RevokeAllForFamily() error = %v", err)
		}

		var revokedAt time.Time
		err = tx.QueryRowContext(ctx, `
			SELECT revoked_at FROM refresh_tokens WHERE token_id = $1
		`, token.ID).Scan(&revokedAt)
		if err != nil {
			t.Fatalf("failed to query revoked token: %v", err)
		}
		if !revokedAt.Equal(originalRevokedAt) {
			t.Errorf("revoked_at = %v, want unchanged value %v", revokedAt, originalRevokedAt)
		}
	})
}

func TestRefreshPostgresRepo_RevokeAllForFamily_NonExistentFamily(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		if err := repo.RevokeAllForFamily(ctx, tx, uuid.New()); err != nil {
			t.Fatalf("RevokeAllForFamily() error = %v, want nil", err)
		}
	})
}

func TestRefreshPostgresRepo_RevokeAllForFamily_ContextCanceled(t *testing.T) {
	withRefreshTx(t, func(ctx context.Context, tx *sql.Tx, repo *refreshPostgresRepo) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		err := repo.RevokeAllForFamily(cctx, tx, uuid.New())
		if err == nil {
			t.Fatal("RevokeAllForFamily() error = nil, want context cancellation error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("RevokeAllForFamily() error = %v, want context.Canceled", err)
		}
	})
}
