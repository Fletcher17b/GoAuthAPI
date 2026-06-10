package models

import "time"

type User struct {
	ID            string
	Email         string
	Username      *string
	PasswordHash  *string
	EmailVerified bool
	IsActive      bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
