package auth

import "context"

type contextKey string

const (
	ContextUserID contextKey = "user_id"
	ContextEmail  contextKey = "email"
)

func UserIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(ContextUserID).(string)
	return id, ok
}

func EmailFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(ContextEmail).(string)
	return email, ok
}
