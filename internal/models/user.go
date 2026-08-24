package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID            uuid.UUID
	Email         string
	Username      *string
	PasswordHash  *string
	EmailVerified bool
	IsActive      bool
	LockedAt      *time.Time
	Tenant_ID     uuid.UUID
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
