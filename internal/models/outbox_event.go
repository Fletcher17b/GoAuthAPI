package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type EventStatus string

const (
	StatusPending    EventStatus = "Pending"
	StatusPublishing EventStatus = "Publishing"
	StatusPublished  EventStatus = "Published"
	StatusFailed     EventStatus = "Failed"
)

type EventType string

const (
	UserCreated EventType = "user.created"
	UserDeleted EventType = "user.deleted"
	UserUpdated EventType = "user.updated"

	EmailVerificationRequested EventType = "email.verification.requested"
	PasswordResetRequested     EventType = "password.reset.requested"
)

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
}
