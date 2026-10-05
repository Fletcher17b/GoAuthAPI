package models

import (
	"time"

	"github.com/google/uuid"
)

type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusPending   TenantStatus = "pending"
)

type Tenant struct {
	ID             uuid.UUID
	TenantName     string // unique, formatted identifier used for lookups
	Name           string // human-readable display name, may contain spaces/symbols
	URL            string
	Email          string
	Status         TenantStatus
	PublicKey      string
	APIKeyHash     string
	AllowedOrigins []string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (t *Tenant) IsActive() bool {
	return t.Status == TenantStatusActive
}
