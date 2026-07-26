package models

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	TokenHash   string
	ClientID    string
	ParentToken uuid.UUID
	FamilyID    uuid.UUID
	ExpiresAt   time.Time
	RevokedAt   *time.Time
	CreatedAt   time.Time
}
