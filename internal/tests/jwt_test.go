package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"AuthAPI/main/internal/auth"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func genTestKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return priv, &priv.PublicKey
}

func TestGenerateAccessToken_ParsesBackWithSameClaims(t *testing.T) {
	priv, pub := genTestKeyPair(t)

	userID := uuid.New()
	email := "user@example.com"

	tokenStr, err := auth.GenerateAccessToken(userID, email, priv)
	require.NoError(t, err)
	require.NotEmpty(t, tokenStr)

	claims, err := auth.ParseAccessToken(tokenStr, pub)
	require.NoError(t, err)
	require.Equal(t, userID, claims.UserID)
	require.Equal(t, email, claims.Email)
	require.Equal(t, userID.String(), claims.Subject)
	require.Equal(t, "auth-service", claims.Issuer)
}

func TestGenerateAccessToken_SetsExpiryAroundFifteenMinutes(t *testing.T) {
	priv, pub := genTestKeyPair(t)

	tokenStr, err := auth.GenerateAccessToken(uuid.New(), "user@example.com", priv)
	require.NoError(t, err)

	claims, err := auth.ParseAccessToken(tokenStr, pub)
	require.NoError(t, err)
	require.NotNil(t, claims.ExpiresAt)

	wantExpiry := time.Now().Add(15 * time.Minute)
	require.WithinDuration(t, wantExpiry, claims.ExpiresAt.Time, 5*time.Second)
}

func TestParseAccessToken_RejectsExpiredToken(t *testing.T) {
	priv, pub := genTestKeyPair(t)

	claims := auth.Claims{
		UserID: uuid.New(),
		Email:  "user@example.com",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   uuid.NewString(),
			Issuer:    "auth-service",
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-30 * time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-15 * time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenStr, err := token.SignedString(priv)
	require.NoError(t, err)

	_, err = auth.ParseAccessToken(tokenStr, pub)
	require.Error(t, err)
}

func TestParseAccessToken_RejectsTokenSignedWithWrongKey(t *testing.T) {
	_, pub := genTestKeyPair(t)
	otherPriv, _ := genTestKeyPair(t)

	tokenStr, err := auth.GenerateAccessToken(uuid.New(), "user@example.com", otherPriv)
	require.NoError(t, err)

	_, err = auth.ParseAccessToken(tokenStr, pub)
	require.Error(t, err)
}

func TestParseAccessToken_RejectsTamperedToken(t *testing.T) {
	priv, pub := genTestKeyPair(t)

	tokenStr, err := auth.GenerateAccessToken(uuid.New(), "user@example.com", priv)
	require.NoError(t, err)
	tampered := tamperMiddleSegment(t, tokenStr)

	_, err = auth.ParseAccessToken(tampered, pub)
	require.Error(t, err)
}

func TestParseAccessToken_RejectsGarbageInput(t *testing.T) {
	_, pub := genTestKeyPair(t)

	_, err := auth.ParseAccessToken("not-a-real-token", pub)
	require.Error(t, err)
}

func TestParseAccessToken_RejectsNonRSASignedToken(t *testing.T) {
	claims := auth.Claims{
		UserID: uuid.New(),
		Email:  "user@example.com",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte("some-secret"))
	require.NoError(t, err)

	_, pub := genTestKeyPair(t)
	_, err = auth.ParseAccessToken(tokenStr, pub)
	require.Error(t, err)
}

/*
func TestGenerateRefreshToken_ReturnsDistinctPlaintextAndHash(t *testing.T) {
	userID := uuid.New()
	familyID := uuid.New()

	// nts TODO update this test for new tenant feature incorporated in GnrRfrTkn
	plain, model, err := auth.GenerateRefreshToken(userID, familyID, uuid.Nil, ,"client-1", "test-secret", )
	require.NoError(t, err)
	require.NotEmpty(t, plain)
	require.NotNil(t, model)

	require.NotEqual(t, plain, model.TokenHash, "the stored hash must not equal the plaintext token")
	require.Equal(t, userID, model.UserID)
	require.Equal(t, familyID, model.FamilyID)
	require.Equal(t, uuid.Nil, model.ParentToken)
	require.Equal(t, "client-1", model.ClientID)
	require.WithinDuration(t, time.Now().Add(30*24*time.Hour), model.ExpiresAt, 5*time.Second)
} */
// nts TODO update this test for new tenant feature incorporated in GnrRfrTkn
/* func TestGenerateRefreshToken_GeneratesUniqueTokensEachCall(t *testing.T) {
	userID := uuid.New()
	familyID := uuid.New()

	plainA, modelA, err := auth.GenerateRefreshToken(userID, familyID, uuid.Nil, "client-1", "test-secret")
	require.NoError(t, err)

	plainB, modelB, err := auth.GenerateRefreshToken(userID, familyID, uuid.Nil, "client-1", "test-secret")
	require.NoError(t, err)

	require.NotEqual(t, plainA, plainB)
	require.NotEqual(t, modelA.TokenHash, modelB.TokenHash)
	require.NotEqual(t, modelA.ID, modelB.ID)
} */

// nts TODO update this test for new tenant feature incorporated in GnrRfrTkn
/* func TestGenerateRefreshToken_SameSecretProducesVerifiableHash(t *testing.T) {
	_, model, err := auth.GenerateRefreshToken(uuid.New(), uuid.New(), uuid.Nil, "client-1", "test-secret")
	require.NoError(t, err)
	require.NotEmpty(t, model.TokenHash)
} */

func TestGenerateEmailVerificationToken_ReturnsDistinctPlaintextAndHash(t *testing.T) {
	userID := uuid.New()

	plain, model, err := auth.GenerateEmailVerificationToken(userID, "test-secret")
	require.NoError(t, err)
	require.NotEmpty(t, plain)
	require.NotNil(t, model)

	require.NotEqual(t, plain, model.TokenHash)
	require.Equal(t, userID, model.UserID)
	require.WithinDuration(t, time.Now().Add(24*time.Hour), model.ExpiresAt, 5*time.Second)
}

func TestGenerateClientID_ReturnsNonEmptyUniqueValues(t *testing.T) {
	a := auth.GenerateClientID()
	b := auth.GenerateClientID()

	require.NotEmpty(t, a)
	require.NotEmpty(t, b)
	require.NotEqual(t, a, b)
}

func tamperMiddleSegment(t *testing.T, tokenStr string) string {
	t.Helper()

	segments := splitJWT(t, tokenStr)
	require.Len(t, segments, 3)

	payload := []byte(segments[1])
	require.NotEmpty(t, payload)

	last := payload[len(payload)-1]
	if last == 'A' {
		payload[len(payload)-1] = 'B'
	} else {
		payload[len(payload)-1] = 'A'
	}

	return segments[0] + "." + string(payload) + "." + segments[2]
}

func splitJWT(t *testing.T, tokenStr string) []string {
	t.Helper()
	var segments []string
	start := 0
	for i, c := range tokenStr {
		if c == '.' {
			segments = append(segments, tokenStr[start:i])
			start = i + 1
		}
	}
	segments = append(segments, tokenStr[start:])
	return segments
}
