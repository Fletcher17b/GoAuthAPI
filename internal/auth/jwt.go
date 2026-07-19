package auth

import (
	"AuthAPI/main/internal/crypto"
	"AuthAPI/main/internal/models"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	UserID uuid.UUID `json:"userid"`
	Email  string    `json:"email"`
	jwt.RegisteredClaims
}

/*
	Access Token expire time: 15 minutes
*/

func GenerateAccessToken(
	userID uuid.UUID,
	email string,
	privateKey *rsa.PrivateKey,
) (string, error) {

	claims := Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Issuer:    "auth-service",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

func generateClientID() string {
	return uuid.NewString()
}

func generateRefreshToken(userID uuid.UUID, clientID, secret string) (string, *models.RefreshToken, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}

	plain := base64.RawURLEncoding.EncodeToString(raw)
	hash := crypto.HashToken(plain, secret)

	now := time.Now()

	rtid, err := uuid.NewV7()
	if err != nil {
		log.Println("Something fucked up in generating refresh token ID jwt file")
	}
	rt := &models.RefreshToken{
		ID:        rtid,
		UserID:    userID,
		ClientID:  clientID,
		TokenHash: hash,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		CreatedAt: now,
	}

	return plain, rt, nil
}

func ParseAccessToken(tokenStr string, pub *rsa.PublicKey) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&Claims{},
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, jwt.ErrInvalidType
			}
			return pub, nil
		},
	)

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}

	return claims, nil
}

func generateEmailVerificationToken(userID uuid.UUID, secret string) (string, *models.EmailVerificationToken, error) {
	raw := make([]byte, 32)
	rand.Read(raw)

	plain := base64.RawURLEncoding.EncodeToString(raw)
	hash := crypto.HashToken(plain, secret)

	now := time.Now()

	id, err := uuid.NewV7()
	if err != nil {
		log.Println("Shit hit the fan in EmailVerification Token in JWT")
	}

	return plain, &models.EmailVerificationToken{
		ID:        id,
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}, nil
}
