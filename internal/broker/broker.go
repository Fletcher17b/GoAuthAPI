package broker

import (
	"AuthAPI/main/internal/models"
	"context"
)

type Broker interface {
	Publish(ctx context.Context, envelope models.EventEnvelope) error

	Close() error
}
