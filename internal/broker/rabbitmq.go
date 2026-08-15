package broker

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

//nolint:unused
type publishResult struct {
	err error
}

/*
	nts: TODO: Need to refactor the publish and overal publishing flow
	currently on publish we dont await nor log confirmation on DBmodel
	we need to refactor that to keep track of ACK and NACK responses
	of the rabbitMQ, also use that logit to coordinate retries
	(republish on nack and if user not verified upon token expiration)
*/

// RabbitMQ is a Broker implementation backed by a single AMQP connection
// and channel, publishing to a topic exchange keyed by routingKey.
type RabbitMQ struct {
	conn    *amqp.Connection
	channel *amqp.Channel

	user_queue *amqp.Queue
	exchange   string

	confirms <-chan amqp.Confirmation
	/* pending map[uint64]chan publishResult
	done chan struct{}
	wg   sync.WaitGroup */

	mu     sync.Mutex // guards channel access, amqp channels are not safe for concurrent publish
	closed bool
}

// NewRabbitMQ dials the given AMQP URL, opens a channel, and declares a durable topic exchange with the given name (created if it doesn't exist).
func NewRabbitMQ(url string, exchange string, logger *slog.Logger) (*RabbitMQ, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		logger.Error("broker: failed to connect to rabbitmq: %w", err.Error(), err)
		return nil, err
	}

	channel, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		logger.Error("broker: failed to open channel: %w", err.Error(), err)
		return nil, err
	}

	if err := channel.ExchangeDeclare(
		exchange,
		"topic",
		true,
		false,
		false,
		false,
		nil,
	); err != nil {
		_ = channel.Close()
		_ = conn.Close()

		errorstring := "broker: failed to declare exchange " + exchange + " : " + err.Error()
		logger.Error(errorstring)

		return nil, err
	}

	if err := channel.Confirm(false); err != nil {
		_ = channel.Close()
		_ = conn.Close()

		errorstring := "broker: failed to put channel in confirm mode: " + err.Error()
		logger.Error(errorstring, err.Error(), err)
		return nil, err
	}

	// name, durable, delete when unused, exclusive, no-wait, arguments
	user_queue, err := channel.QueueDeclare(
		"user_service_queue",
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		errorstring := "broker: failed to put channel in confirm mode: " + err.Error()
		logger.Error(errorstring, err.Error(), err)
		return nil, err
	}

	if err := channel.QueueBind(user_queue.Name, "user.#", exchange, false, nil); err != nil {
		_ = channel.Close()
		_ = conn.Close()
		logger.Error("broker: failed to bind user_service_queue", "error", err)
		return nil, err
	}

	confirms := channel.NotifyPublish(
		make(chan amqp.Confirmation, 100),
	)

	return &RabbitMQ{
		conn:       conn,
		channel:    channel,
		exchange:   exchange,
		user_queue: &user_queue,
		confirms:   confirms,
		/* pending:  make(map[uint64]chan publishResult),
		done:     make(chan struct{}), */
	}, nil
}

/*
nts: publish sends payload to the configured exchange using routingKey,
*/
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

	/* deliveryTag := r.channel.GetNextPublishSeqNo()
	resultCh := make(chan publishResult, 1)
	r.pending[deliveryTag] = resultCh
	*/
	err := r.channel.PublishWithContext(
		ctx,
		r.exchange,
		routingKey,
		true,  // mandatory
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
		return fmt.Errorf(
			"broker: failed to publish to %q: %w",
			routingKey,
			err,
		)
	}

	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()

	select {
	case confirm, ok := <-r.confirms:
		if !ok {
			return fmt.Errorf(
				"broker: confirmation channel closed before ack for %q",
				routingKey,
			)
		}

		log.Println("rabbitmq publisher confirmation",
			"delivery_tag", confirm.DeliveryTag,
			"ack", confirm.Ack)

		if !confirm.Ack {
			return fmt.Errorf(
				"broker: broker nacked message for %q",
				routingKey,
			)
		}

		return nil
	case <-timeout.C:
		return fmt.Errorf(
			"broker: timed out waiting for confirmation for %q",
			routingKey,
		)

	case <-ctx.Done():
		return fmt.Errorf(
			"broker: publish to %q cancelled: %w",
			routingKey,
			ctx.Err(),
		)
	}

	/*
		if err != nil {
			delete(r.pending, deliveryTag)

			return fmt.Errorf(
				"broker: failed to publish to %q: %w",
				routingKey,
				err,
			)
		}
	*/
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

/*
func (r *RabbitMQ) confirmationLoop() {
	defer r.wg.Done()
	for {
		select {
		case <-r.done:
			return
		case confirm, ok := <-r.confirms:
			if !ok {
				r.failPending(
					fmt.Errorf("broker: confirmation channel closed"),
				)
				return
			}
			r.handleConfirmation(confirm)
		}
	}
}

func (r *RabbitMQ) handleConfirmation(
	confirm amqp.Confirmation,
) {
	r.mu.Lock()

	publish, ok := r.pending[confirm.DeliveryTag]
	delete(r.pending, confirm.DeliveryTag)

	r.mu.Unlock()

	if !ok {
		r.logger.Warn(
			"rabbitmq: confirmation for unknown delivery tag",
			"delivery_tag", confirm.DeliveryTag,
		)
		return
	}

	if confirm.Ack {
		r.logger.Info(
			"rabbitmq: publisher confirmation",
			"delivery_tag", confirm.DeliveryTag,
			"routing_key", publish.routingKey,
		)
		return
	}

	r.logger.Error( "rabbitmq: publisher NACK",
		"delivery_tag", confirm.DeliveryTag,
		"routing_key", publish.routingKey, )}
*/
