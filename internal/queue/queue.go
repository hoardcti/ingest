// Package queue carries envelopes from collectors to the ingest service.
//
// Redis Streams is the default transport because Redis is already running for
// the IOC lookup cache, so it adds no new infrastructure while still providing
// consumer groups, acknowledgements and replay. If several independent consumer
// groups ever need the same stream — ingest, enrichment, alerting — that is the
// point to move to NATS JetStream, and the [Consumer] and [Publisher]
// interfaces here are the seam to do it behind.
package queue

import (
	"context"
	"time"
)

// Message is one envelope as it came off the transport.
type Message struct {
	// ID is the transport's identifier, used to acknowledge the message.
	ID string

	// Body is the raw envelope JSON.
	Body []byte

	// Deliveries counts how many times this message has been handed out. A
	// message that keeps coming back is a poison message, and the service
	// dead-letters it rather than letting it stall the group forever.
	Deliveries int64
}

// Consumer reads envelopes from the transport.
//
// Delivery is at-least-once. The ingest service makes that harmless by claiming
// an idempotency row inside the same transaction as the write, so a redelivered
// envelope is recognised and skipped.
type Consumer interface {
	// Receive returns up to max messages, blocking for at most block if none
	// are ready. An empty slice with a nil error means the block elapsed.
	Receive(ctx context.Context, max int, block time.Duration) ([]Message, error)

	// Ack marks messages as processed. Unacknowledged messages are redelivered
	// after the visibility timeout.
	Ack(ctx context.Context, ids ...string) error

	// Pending reports how many messages the group has delivered but not had
	// acknowledged. This is the number to alert on.
	Pending(ctx context.Context) (int64, error)

	// Backlog reports how many messages are waiting to be delivered at all.
	Backlog(ctx context.Context) (int64, error)

	Close() error
	Name() string
}

// Publisher writes envelopes to the transport. The HTTP intake uses it so that
// a collector without a Redis client can still submit, without becoming a
// second writer to Postgres.
type Publisher interface {
	Publish(ctx context.Context, body []byte) (id string, err error)
	Close() error
	Name() string
}
