package models

import "time"

type RefreshToken struct {
	ID        string
	UserID    string
	ClientID  string
	TokenHash string
	/* IPAddress string */
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}
