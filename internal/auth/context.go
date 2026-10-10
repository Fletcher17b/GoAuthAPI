package auth

import (
	"AuthAPI/main/internal/models"
	"context"
)

type ctxKey string

const (
	ContextUserID    ctxKey = "user_id"
	ContextEmail     ctxKey = "email"
	ContextTenant    ctxKey = "tenant"
	ContextRequestID ctxKey = "request_id"
	//ContextConsumerID ctxKey = "consumer_id"
)

func UserIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(ContextUserID).(string)
	return id, ok
}

func EmailFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(ContextEmail).(string)
	return email, ok
}

/*
	 func ConsumerIDFromContext(ctx context.Context) (string, bool) {
		id, ok := ctx.Value(ContextConsumerID).(string)
		return id, ok
	}
*/
func TenantFromContext(ctx context.Context) (*models.Tenant, bool) {
	tenant, ok := ctx.Value(ContextTenant).(*models.Tenant)
	return tenant, ok
}
