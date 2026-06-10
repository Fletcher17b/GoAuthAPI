package auth

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/google/uuid"

	"AuthAPI/main/internal/crypto"
	"AuthAPI/main/internal/models"
)

func generateRefreshToken(userID, secret string) (string, *models.RefreshToken, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}

	plain := base64.RawURLEncoding.EncodeToString(raw)
	hash := crypto.HashToken(plain, secret)

	now := time.Now()

	rt := &models.RefreshToken{
		ID:        uuid.NewString(),
		UserID:    userID,
		TokenHash: hash,
		/* IPAddress: ip, */
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		CreatedAt: now,
	}

	return plain, rt, nil
}
