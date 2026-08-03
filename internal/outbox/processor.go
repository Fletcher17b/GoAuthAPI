package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"time"

	"AuthAPI/main/internal/broker"
	"AuthAPI/main/internal/models"
)

const (
	maxRetries  = 8
	baseBackoff = 2 * time.Second
	maxBackoff  = 5 * time.Minute
)

type Processor struct {
	repo   OutboxRepo
	broker broker.Broker
}

func NewProcessor(repo OutboxRepo, b broker.Broker) *Processor {
	return &Processor{
		repo:   repo,
		broker: b,
	}
}

func (p *Processor) ProcessBatch(ctx context.Context, batchSize int) (int, error) {
	events, err := p.repo.FetchPending(ctx, batchSize)
	if err != nil {
		return 0, fmt.Errorf("outbox: failed to fetch pending events: %w", err)
	}

	var firstErr error
	for _, event := range events {
		if err := p.processOne(ctx, event); err != nil {
			log.Printf("outbox: failed to process event %s (%s): %v", event.ID, event.EventType, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	return len(events), firstErr
}

func (p *Processor) processOne(ctx context.Context, event *models.OutboxEvent) error {
	headers, err := decodeHeaders(event.Headers)
	if err != nil {
		// Malformed headers aren't going to fix themselves on retry, but we
		// still record the failure rather than dropping the event silently.
		return p.fail(ctx, event, fmt.Errorf("invalid headers: %w", err))
	}

	routingKey := string(event.EventType)

	if err := p.broker.Publish(ctx, routingKey, event.Payload, headers); err != nil {
		return p.fail(ctx, event, err)
	}

	if err := p.repo.MarkPublished(ctx, event.ID, time.Now()); err != nil {
		return fmt.Errorf("failed to mark event %s published: %w", event.ID, err)
	}

	return nil
}

func (p *Processor) fail(ctx context.Context, event *models.OutboxEvent, cause error) error {
	nextRetryAt := time.Now().Add(backoffFor(event.RetryCount))

	if markErr := p.repo.MarkFailed(ctx, event.ID, nextRetryAt, cause.Error()); markErr != nil {
		return fmt.Errorf("publish failed (%v) and failed to record failure: %w", cause, markErr)
	}

	if event.RetryCount+1 >= maxRetries {
		log.Printf("outbox: event %s (%s) has exceeded max retries (%d): %v", event.ID, event.EventType, maxRetries, cause)
	}

	return cause
}

// backoffFor returns an exponential backoff duration (base * 2^retryCount),
// capped at maxBackoff.
func backoffFor(retryCount int) time.Duration {
	backoff := float64(baseBackoff) * math.Pow(2, float64(retryCount))
	if backoff > float64(maxBackoff) {
		return maxBackoff
	}
	return time.Duration(backoff)
}

func decodeHeaders(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	var headers map[string]any
	if err := json.Unmarshal(raw, &headers); err != nil {
		return nil, err
	}
	return headers, nil
}
