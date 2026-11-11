package models

import (
	"time"

	"github.com/google/uuid"
)

/*
	Right now we handle the API Key as UUID v7
	On the future it would be convinient to handle it as a format:
	auth_{consumer}_uuidv7 eg: auth_acme_018a12b4-e3f7-7b3a-9c2d-1a2b3c4d5e6f
*/

type Apikey_model struct {
	Apikey_ID uuid.UUID `db:"apikey_id"`
	Keyhash   uuid.UUID `db:"apikey_hash"`
	KeyOwner  uuid.UUID `db:"apikeyowner_id"`

	Keyname string `db:"name"`

	Revoked   bool
	RevokedAt *time.Time
	ExpiresAt time.Time
	CreatedAt time.Time
}
