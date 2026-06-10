package models

type UserRole struct {
	UserID string `db:"user_id"`
	Role   string `db:"role"`
}
