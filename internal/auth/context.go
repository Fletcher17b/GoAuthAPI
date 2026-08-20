package auth

import (
	"AuthAPI/main/internal/models"
	"context"
)

type contextKey string

const (
	ContextUserID contextKey = "user_id"
	ContextEmail  contextKey = "email"
	ContextTenant contextKey = "tenant"
)

func UserIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(ContextUserID).(string)
	return id, ok
}

func EmailFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(ContextEmail).(string)
	return email, ok
}

func TenantFromContext(ctx context.Context) (*models.Tenant, bool) {
	tenant, ok := ctx.Value(ContextTenant).(*models.Tenant)
	return tenant, ok
}
