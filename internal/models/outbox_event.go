package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type EventStatus string

const (
	StatusPending    EventStatus = "pending"
	StatusProcessing EventStatus = "processing"
	StatusPublishing EventStatus = "publishing"
	StatusPublished  EventStatus = "published"
	StatusFailed     EventStatus = "failed"
)

type EventType string

const (
	UserCreated                EventType = "user.created"
	UserUpdated                EventType = "user.updated"
	UserDeleted                EventType = "user.deleted"
	UserLoginSucceeded         EventType = "user.login.succeeded"
	UserLoginFailed            EventType = "user.login.failed"
	UserPasswordResetRequired  EventType = "user.password_reset.required"
	UserPasswordResetSucceeded EventType = "user.password_reset.succeeded"

	EmailVerificationRequested  EventType = "email.verification.requested"
	EmailPasswordResetRequested EventType = "email.password_reset.requested"
	EmailNewDeviceLogin         EventType = "email.new_device_login"
)

type EventEnvelope struct {
	EventID   uuid.UUID       `json:"event_id"`
	EventType EventType       `json:"event_type"`
	Payload   json.RawMessage `json:"payload"`
	Headers   map[string]any  `json:"headers,omitempty"`
}

type EmailPayloadContext struct {
	Tenant   string    `json:"tenant"`
	UserID   uuid.UUID `json:"user_id"`
	Email    string    `json:"email"`
	Username *string   `json:"username,omitempty"`

	EventID     uuid.UUID `json:"event_id,omitempty"`
	IP          string    `json:"ip,omitempty"`
	PayloadData any       `json:"data,omitempty"`
}

type EmailVerificationRequestPayload struct {
	VerificationUrl string    `json:"verification_url"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type PasswordResetRequestedPayload struct {
	ResetLink string `json:"reset_link"`
}

/* To do add per tenant URL in the Tenant Policies config in DB */
type NewDeviceLoginPayload struct {
	UserAgent        string    `json:"user_agent"`
	IP               string    `json:"ip"`
	LoginAt          time.Time `json:"login_at"`
	SecureAccountURL string    `json:"secure_account_url"` // "wasn't me" link
}

type OutboxEvent struct {
	ID            uuid.UUID       `db:"id" json:"id"`
	AggregateType string          `db:"aggregate_type" json:"aggregate_type"`
	AggregateID   uuid.UUID       `db:"aggregate_id" json:"aggregate_id"`
	EventType     EventType       `db:"event_type" json:"event_type"`
	Payload       json.RawMessage `db:"payload"`
	Headers       json.RawMessage `db:"headers" json:"headers,omitempty"` // nullable raw JSON bytes
	Status        EventStatus     `db:"status" json:"status"`
	RetryCount    int             `db:"retry_count" json:"retry_count"`
	NextRetryAt   time.Time       `db:"next_retry_at" json:"next_retry_at"`
	CreatedAt     time.Time       `db:"created_at" json:"created_at"`
	PublishedAt   *time.Time      `db:"published_at" json:"published_at,omitempty"` // pointer for nullable timestamp
	LastError     *string         `db:"last_error" json:"last_error,omitempty"`     // pointer for nullable text

	// Claim/lock tracking for concurrent worker instances. A row is
	// claimed by setting status=processing and populating all three of
	// these in the same statement that performed the claim; a claim past
	// LockedUntil is considered abandoned (crashed worker) and eligible
	// for reclaim by ClaimBatch.
	LockedAt    *time.Time `db:"locked_at" json:"locked_at,omitempty"`
	LockedUntil *time.Time `db:"locked_until" json:"locked_until,omitempty"`
	LockedBy    *string    `db:"locked_by" json:"locked_by,omitempty"`
}
