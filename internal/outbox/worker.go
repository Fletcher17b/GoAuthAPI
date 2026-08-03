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

func defaultWorkerConfig() WorkerConfig {
	return WorkerConfig{
		PollInterval: 5 * time.Second,
		BatchSize:    50,
	}
}

// Worker periodically drives a Processor to publish due outbox events.
type Worker struct {
	processor *Processor
	cfg       WorkerConfig

	stopped chan struct{}
}

// NewWorker builds a Worker. Zero-value fields in cfg fall back to sane
// defaults (5s poll interval, batch size 50).
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

// Run blocks, polling on cfg.PollInterval until ctx is cancelled. Intended
// to be launched with `go worker.Run(ctx)`.
func (w *Worker) Run(ctx context.Context) {
	defer close(w.stopped)

	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()

	// Do an initial pass immediately instead of waiting for the first tick.
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

// Stopped returns a channel that's closed once Run has returned, useful
// for waiting on graceful shutdown from the caller.
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
