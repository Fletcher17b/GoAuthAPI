package outbox

import (
	"context"
	"log"
	"time"
)

type WorkerConfig struct {
	PollInterval time.Duration
	BatchSize    int
}

// Worker periodically drives a Processor to publish due outbox events.
type Worker struct {
	processor *Processor
	cfg       WorkerConfig

	stopped chan struct{}
}

func defaultWorkerConfig() WorkerConfig {
	return WorkerConfig{
		PollInterval: 5 * time.Second,
		BatchSize:    50,
	}
}

// Run blocks, polling on cfg.PollInterval until ctx is cancelled. Intended use: `go worker.Run(ctx)`.
func (w *Worker) Run(ctx context.Context) {
	defer close(w.stopped)

	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()

	w.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Println("outbox: worker shutting down")
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

func NewWorker(processor *Processor, cfg WorkerConfig) *Worker {
	defaults := defaultWorkerConfig()
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaults.PollInterval
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaults.BatchSize
	}

	return &Worker{
		processor: processor,
		cfg:       cfg,
		stopped:   make(chan struct{}),
	}
}

func (w *Worker) Stopped() <-chan struct{} {
	return w.stopped
}

func (w *Worker) tick(ctx context.Context) {
	processed, err := w.processor.ProcessBatch(ctx, w.cfg.BatchSize)
	if err != nil {
		log.Printf("outbox: batch of %d event(s) processed with errors: %v", processed, err)
		return
	}
	if processed > 0 {
		log.Printf("outbox: processed %d event(s)", processed)
	}
}
