package broker

import (
	"context"
	"fmt"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// RabbitMQ is a Broker implementation backed by a single AMQP connection
// and channel, publishing to a topic exchange keyed by routingKey.
type RabbitMQ struct {
	conn    *amqp.Connection
	channel *amqp.Channel

	exchange string

	mu     sync.Mutex // guards channel access, amqp channels are not safe for concurrent publish
	closed bool
}

// NewRabbitMQ dials the given AMQP URL, opens a channel, and declares a
// durable topic exchange with the given name (created if it doesn't exist).
func NewRabbitMQ(url string, exchange string) (*RabbitMQ, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, fmt.Errorf("broker: failed to connect to rabbitmq: %w", err)
	}

	channel, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("broker: failed to open channel: %w", err)
	}

	if err := channel.ExchangeDeclare(
		exchange,
		"topic",
		true,  // durable
		false, // auto-deleted
		false, // internal
		false, // no-wait
		nil,
	); err != nil {
		_ = channel.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("broker: failed to declare exchange %q: %w", exchange, err)
	}

	// Publisher confirms let us know the broker actually accepted the message.
	if err := channel.Confirm(false); err != nil {
		_ = channel.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("broker: failed to put channel in confirm mode: %w", err)
	}

	return &RabbitMQ{
		conn:     conn,
		channel:  channel,
		exchange: exchange,
	}, nil
}

// Publish sends payload to the configured exchange using routingKey,
// waiting for the broker's publisher confirm (or ctx cancellation) before
// returning.
func (r *RabbitMQ) Publish(
	ctx context.Context,
	routingKey string,
	payload []byte,
	headers map[string]any,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return fmt.Errorf("broker: publish called on closed connection")
	}

	confirms := r.channel.NotifyPublish(make(chan amqp.Confirmation, 1))

	err := r.channel.PublishWithContext(
		ctx,
		r.exchange,
		routingKey,
		true,  // mandatory: return the message if it can't be routed
		false, // immediate
		amqp.Publishing{
			ContentType:  "application/json",
			DeliveryMode: amqp.Persistent,
			Timestamp:    time.Now(),
			Headers:      toAMQPTable(headers),
			Body:         payload,
		},
	)
	if err != nil {
		return fmt.Errorf("broker: failed to publish to %q: %w", routingKey, err)
	}

	select {
	case confirm, ok := <-confirms:
		if !ok {
			return fmt.Errorf("broker: confirmation channel closed before ack for %q", routingKey)
		}
		if !confirm.Ack {
			return fmt.Errorf("broker: broker nacked message for %q", routingKey)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("broker: publish to %q cancelled: %w", routingKey, ctx.Err())
	}
}

// Close tears down the channel and connection. Safe to call more than once.
func (r *RabbitMQ) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true

	var chErr, connErr error
	if r.channel != nil {
		chErr = r.channel.Close()
	}
	if r.conn != nil {
		connErr = r.conn.Close()
	}

	if chErr != nil {
		return fmt.Errorf("broker: error closing channel: %w", chErr)
	}
	if connErr != nil {
		return fmt.Errorf("broker: error closing connection: %w", connErr)
	}
	return nil
}

func toAMQPTable(headers map[string]any) amqp.Table {
	if len(headers) == 0 {
		return nil
	}
	table := make(amqp.Table, len(headers))
	for k, v := range headers {
		table[k] = v
	}
	return table
}
