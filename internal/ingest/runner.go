package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/hoardcti/ingest/internal/queue"
	"github.com/hoardcti/ingest/internal/telemetry"
)

// RunnerOptions configure the consumer loop.
type RunnerOptions struct {
	// Workers is how many envelopes are processed concurrently. Each one holds
	// a database transaction for the length of its batch, so this should stay
	// well under the connection pool size.
	Workers int

	// Prefetch is how many messages to ask the transport for at a time.
	Prefetch int

	// BlockTimeout is how long to wait for new messages before looping. It
	// bounds how quickly the runner notices a cancelled context.
	BlockTimeout time.Duration

	// MaxDeliveries is how many times a message may be redelivered before it is
	// treated as poison and parked. Without this, an envelope that triggers a
	// bug in the write path is redelivered forever and the consumer group never
	// makes progress past it.
	MaxDeliveries int64

	// StatsInterval is how often queue depth is sampled for metrics.
	StatsInterval time.Duration

	Logger  *slog.Logger
	Metrics *telemetry.Metrics
}

func (o *RunnerOptions) setDefaults() {
	if o.Workers <= 0 {
		o.Workers = 4
	}
	if o.Prefetch <= 0 {
		o.Prefetch = o.Workers * 2
	}
	if o.BlockTimeout <= 0 {
		o.BlockTimeout = 5 * time.Second
	}
	if o.MaxDeliveries <= 0 {
		o.MaxDeliveries = 5
	}
	if o.StatsInterval <= 0 {
		o.StatsInterval = 15 * time.Second
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
}

// Runner consumes envelopes from a transport and feeds them to the service.
type Runner struct {
	svc      *Service
	consumer queue.Consumer
	opts     RunnerOptions
	log      *slog.Logger
}

// NewRunner builds a consumer loop.
func NewRunner(svc *Service, consumer queue.Consumer, opts RunnerOptions) *Runner {
	opts.setDefaults()
	return &Runner{svc: svc, consumer: consumer, opts: opts, log: opts.Logger}
}

// Run consumes until ctx is cancelled, then drains work already in flight and
// returns.
//
// One reader, several workers: the transport hands messages to a single
// consumer name, and fanning them out here keeps that contract while still
// overlapping the database round trips that dominate the time.
func (r *Runner) Run(ctx context.Context) error {
	r.log.Info("ingest runner starting",
		"transport", r.consumer.Name(),
		"workers", r.opts.Workers,
		"prefetch", r.opts.Prefetch,
		"archive", r.svc.Archive().Name(),
		"cache", r.svc.Cache().Name())

	work := make(chan queue.Message, r.opts.Prefetch)

	var wg sync.WaitGroup
	for i := 0; i < r.opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for msg := range work {
				r.handle(ctx, msg)
			}
		}()
	}

	statsDone := make(chan struct{})
	go func() {
		defer close(statsDone)
		r.sampleQueue(ctx)
	}()

	err := r.read(ctx, work)

	close(work)
	wg.Wait()
	<-statsDone

	r.log.Info("ingest runner stopped")
	return err
}

func (r *Runner) read(ctx context.Context, work chan<- queue.Message) error {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		if ctx.Err() != nil {
			return nil
		}

		msgs, err := r.consumer.Receive(ctx, r.opts.Prefetch, r.opts.BlockTimeout)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return nil
			}
			// The transport is down. Keep trying rather than exiting: a
			// restart loop against a Redis that is briefly unavailable is
			// noise, and the collectors are still filling the stream.
			r.log.Error("receive from queue failed; retrying",
				"error", err, "retry_in", backoff)
			if !sleep(ctx, backoff) {
				return nil
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		backoff = time.Second

		for _, m := range msgs {
			select {
			case work <- m:
			case <-ctx.Done():
				return nil
			}
		}
	}
}

// handle processes one message and decides its fate on the queue.
func (r *Runner) handle(ctx context.Context, msg queue.Message) {
	// Processing follows the runner's context, so a shutdown aborts the
	// transaction rather than holding it open — nothing is lost, because the
	// message stays unacknowledged and the write was atomic. Acknowledging and
	// dead-lettering do NOT follow it: those must still complete during a
	// shutdown, or a message that was fully processed comes back as a
	// duplicate, and a poison message comes back forever.
	log := r.log.With("message_id", msg.ID, "deliveries", msg.Deliveries)

	if len(msg.Body) == 0 {
		log.Warn("message has no envelope field; acknowledging")
		r.ack(ctx, msg.ID)
		return
	}

	if msg.Deliveries > r.opts.MaxDeliveries {
		log.Error("message exceeded delivery limit; parking as poison",
			"limit", r.opts.MaxDeliveries)
		r.park(ctx, msg, "poison", "exceeded delivery limit; a retryable failure "+
			"kept recurring, so it is almost certainly not retryable")
		return
	}

	res, err := r.svc.Process(ctx, msg.Body)
	switch {
	case err == nil:
		if res.Duplicate {
			log.Debug("duplicate envelope acknowledged",
				"source", res.Source, "digest", res.Digest)
		} else {
			log.Info("envelope ingested",
				"source", res.Source,
				"records", res.RecordsWritten,
				"dropped", res.RecordsDropped,
				"sightings", res.Sightings,
				"relationships", res.Relationships,
				"elapsed", res.Elapsed.Round(time.Millisecond))
		}
		r.ack(ctx, msg.ID)

	case IsPermanent(err):
		log.Error("envelope rejected; parking",
			"source", res.Source, "stage", Stage(err), "error", err)
		r.park(ctx, msg, Stage(err), err.Error())

	case ctx.Err() != nil:
		// Shutting down. Leave it unacknowledged so it is redelivered to
		// whoever picks up the group next.
		log.Info("shutdown during processing; leaving message for redelivery",
			"source", res.Source)

	default:
		// Transient. Not acknowledged, so the transport redelivers it once the
		// visibility timeout expires.
		r.opts.Metrics.ObserveEnvelope(res.Source, telemetry.OutcomeRetry)
		log.Error("envelope failed; will be redelivered",
			"source", res.Source, "error", err)
	}
}

// park dead-letters a message and acknowledges it, so one bad envelope cannot
// stall the group.
func (r *Runner) park(ctx context.Context, msg queue.Message, stage, reason string) {
	// Use a fresh context: parking is exactly what we want to succeed when the
	// runner is being torn down.
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()

	source := sourceOf(msg.Body)
	if err := r.svc.Store().DeadLetter(pctx, source, msg.ID, stage, reason, msg.Body); err != nil {
		// Could not record it. Do NOT acknowledge — redelivery is better than
		// dropping an envelope on the floor with no trace of it anywhere.
		r.log.Error("could not record dead letter; leaving message unacknowledged",
			"message_id", msg.ID, "error", err)
		return
	}
	r.opts.Metrics.ObserveEnvelope(source, telemetry.OutcomeDeadLetter)
	r.ack(pctx, msg.ID)
}

func (r *Runner) ack(ctx context.Context, id string) {
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()

	if err := r.consumer.Ack(actx, id); err != nil {
		// The work is committed; a failed ack only means a redelivery, which
		// the idempotency claim will absorb.
		r.log.Warn("acknowledge failed; envelope will be redelivered and skipped",
			"message_id", id, "error", err)
	}
}

func (r *Runner) sampleQueue(ctx context.Context) {
	if r.opts.Metrics == nil {
		return
	}
	t := time.NewTicker(r.opts.StatsInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			backlog, err := r.consumer.Backlog(ctx)
			if err != nil {
				continue
			}
			pending, err := r.consumer.Pending(ctx)
			if err != nil {
				continue
			}
			r.opts.Metrics.ObserveQueue(backlog, pending)
		}
	}
}

// sourceOf pulls the source slug out of a message without fully decoding it, so
// a dead letter from a malformed envelope is still attributable.
func sourceOf(body []byte) string {
	var probe struct {
		Source string `json:"source"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return ""
	}
	return probe.Source
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
