package models

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ClientID  string
	TokenHash string
	/* IPAddress string */
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}
