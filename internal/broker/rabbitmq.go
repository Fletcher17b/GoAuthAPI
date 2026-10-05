package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"AuthAPI/main/internal/models"

	amqp "github.com/rabbitmq/amqp091-go"
)

// pendingPublish tracks one in-flight publish awaiting a broker
// confirmation, keyed by its AMQP publish sequence number.
type pendingPublish struct {
	routingKey string
	result     chan error
}

// RabbitMQ is a Broker implementation backed by a single AMQP connection
// and channel, publishing to a topic exchange. Auth only ever declares
// and publishes to the exchange - it does not declare or bind any
// queues. Queue ownership belongs to each downstream consumer service
// (mail, sms, push), which independently declares its own queue against
// this exchange on its own startup.
type RabbitMQ struct {
	conn    *amqp.Connection
	channel *amqp.Channel

	exchange string
	logger   *slog.Logger

	confirms <-chan amqp.Confirmation

	pendingMu sync.Mutex
	pending   map[uint64]*pendingPublish

	publishMu sync.Mutex // serializes PublishWithContext + GetNextPublishSeqNo, since an amqp.Channel is not safe for concurrent use

	done chan struct{}
	wg   sync.WaitGroup

	closeMu sync.Mutex
	closed  bool
}

// NewRabbitMQ dials the given AMQP URL, opens a channel, and declares a
// durable topic exchange with the given name (created if it doesn't
// exist). It declares nothing else - no queues, no bindings. Consumers
// own their own queue topology.
func NewRabbitMQ(url string, exchange string, logger *slog.Logger) (*RabbitMQ, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		logger.Error("broker: failed to connect to rabbitmq", "error", err)
		return nil, err
	}

	channel, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		logger.Error("broker: failed to open channel", "error", err)
		return nil, err
	}

	if err := channel.ExchangeDeclare(
		exchange,
		"topic",
		true,  // durable
		false, // autoDelete
		false, // internal
		false, // noWait
		nil,
	); err != nil {
		_ = channel.Close()
		_ = conn.Close()
		logger.Error("broker: failed to declare exchange", "exchange", exchange, "error", err)
		return nil, err
	}

	if err := channel.Confirm(false); err != nil {
		_ = channel.Close()
		_ = conn.Close()
		logger.Error("broker: failed to put channel in confirm mode", "error", err)
		return nil, err
	}

	confirms := channel.NotifyPublish(make(chan amqp.Confirmation, 100))

	r := &RabbitMQ{
		conn:     conn,
		channel:  channel,
		exchange: exchange,
		logger:   logger,
		confirms: confirms,
		pending:  make(map[uint64]*pendingPublish),
		done:     make(chan struct{}),
	}

	r.wg.Add(1)
	go r.confirmationLoop()

	return r, nil
}

// confirmationLoop reads every confirmation off the channel and dispatches
// it to whichever Publish call is waiting on that sequence number. This
// lets multiple goroutines call Publish concurrently without blocking on
// each other's confirmations - each gets its own result channel.
func (r *RabbitMQ) confirmationLoop() {
	defer r.wg.Done()

	for {
		select {
		case <-r.done:
			r.failAllPending(errors.New("broker: connection closed"))
			return

		case confirm, ok := <-r.confirms:
			if !ok {
				r.failAllPending(errors.New("broker: confirmation channel closed"))
				return
			}
			r.handleConfirmation(confirm)
		}
	}
}

func (r *RabbitMQ) handleConfirmation(confirm amqp.Confirmation) {
	r.pendingMu.Lock()
	p, ok := r.pending[confirm.DeliveryTag]
	delete(r.pending, confirm.DeliveryTag)
	r.pendingMu.Unlock()

	if !ok {
		r.logger.Warn("broker: confirmation for unknown delivery tag", "delivery_tag", confirm.DeliveryTag)
		return
	}

	if confirm.Ack {
		r.logger.Info("broker: publisher confirmation received",
			"delivery_tag", confirm.DeliveryTag,
			"routing_key", p.routingKey,
			"ack", true,
		)
		p.result <- nil
		return
	}

	r.logger.Error("broker: publisher nack received",
		"delivery_tag", confirm.DeliveryTag,
		"routing_key", p.routingKey,
	)
	p.result <- fmt.Errorf("broker: broker nacked message for %q", p.routingKey)
}

func (r *RabbitMQ) failAllPending(cause error) {
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()

	for tag, p := range r.pending {
		p.result <- cause
		delete(r.pending, tag)
	}
}

// Publish sends envelope to the configured exchange. The routing key is
// always string(envelope.EventType) - never supplied by the caller - so
// the key and the payload it describes can never drift apart.
func (r *RabbitMQ) Publish(ctx context.Context, envelope models.EventEnvelope) error {
	r.closeMu.Lock()
	closed := r.closed
	r.closeMu.Unlock()
	if closed {
		return errors.New("broker: publish called on closed connection")
	}

	routingKey := string(envelope.EventType)

	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("broker: failed to marshal envelope for %q: %w", routingKey, err)
	}

	resultCh := make(chan error, 1)

	r.publishMu.Lock()
	seqNo := r.channel.GetNextPublishSeqNo()

	r.pendingMu.Lock()
	r.pending[seqNo] = &pendingPublish{routingKey: routingKey, result: resultCh}
	r.pendingMu.Unlock()

	err = r.channel.PublishWithContext(
		ctx,
		r.exchange,
		routingKey,
		true,  // mandatory
		false, // immediate
		amqp.Publishing{
			ContentType:  "application/json",
			DeliveryMode: amqp.Persistent,
			Timestamp:    time.Now(),
			MessageId:    envelope.EventID.String(),
			Body:         body,
		},
	)
	r.publishMu.Unlock()

	if err != nil {
		r.pendingMu.Lock()
		delete(r.pending, seqNo)
		r.pendingMu.Unlock()

		r.logger.Error("broker: failed to publish", "routing_key", routingKey, "error", err)
		return fmt.Errorf("broker: failed to publish to %q: %w", routingKey, err)
	}

	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()

	select {
	case confirmErr := <-resultCh:
		return confirmErr

	case <-timeout.C:
		r.pendingMu.Lock()
		delete(r.pending, seqNo)
		r.pendingMu.Unlock()

		r.logger.Error("broker: timed out waiting for confirmation", "routing_key", routingKey, "seq_no", seqNo)
		return fmt.Errorf("broker: timed out waiting for confirmation for %q", routingKey)

	case <-ctx.Done():
		r.pendingMu.Lock()
		delete(r.pending, seqNo)
		r.pendingMu.Unlock()

		r.logger.Error("broker: publish cancelled", "routing_key", routingKey, "error", ctx.Err())
		return fmt.Errorf("broker: publish to %q cancelled: %w", routingKey, ctx.Err())
	}
}

// Close tears down the confirmation loop, channel, and connection. Safe
// to call more than once.
func (r *RabbitMQ) Close() error {
	r.closeMu.Lock()
	if r.closed {
		r.closeMu.Unlock()
		return nil
	}
	r.closed = true
	r.closeMu.Unlock()

	close(r.done)
	r.wg.Wait()

	var chErr, connErr error
	if r.channel != nil {
		chErr = r.channel.Close()
	}
	if r.conn != nil {
		connErr = r.conn.Close()
	}

	if chErr != nil {
		r.logger.Error("broker: error closing channel", "error", chErr)
		return fmt.Errorf("broker: error closing channel: %w", chErr)
	}
	if connErr != nil {
		r.logger.Error("broker: error closing connection", "error", connErr)
		return fmt.Errorf("broker: error closing connection: %w", connErr)
	}
	return nil
}
