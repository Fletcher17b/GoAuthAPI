package models

import "time"

type OAuthIdentity struct {
	ID              string    `db:"id"`
	UserID          string    `db:"user_id"`
	Provider        string    `db:"provider"`
	ProviderUserID  string    `db:"provider_user_id"`
	EmailAtProvider string    `db:"email_at_provider"`
	CreatedAt       time.Time `db:"created_at"`
}
