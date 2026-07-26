package broker

import "context"

type Broker interface {
	Publish(
		ctx context.Context,
		routingKey string,
		payload []byte,
		headers map[string]any,
	) error

	Close() error
}
