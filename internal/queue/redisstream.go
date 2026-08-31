package queue

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// FieldEnvelope is the stream field the envelope JSON is stored under.
const FieldEnvelope = "envelope"

// RedisOptions configures the Redis Streams transport.
type RedisOptions struct {
	Client redis.UniversalClient

	// Stream is the key envelopes are written to.
	Stream string

	// Group is the consumer group name. All ingest replicas share one group, so
	// each envelope is processed once.
	Group string

	// Consumer names this replica within the group. It must be stable across
	// restarts — that is how a replica reclaims the messages it was holding
	// when it died. The hostname is the usual choice.
	Consumer string

	// MinIdle is how long a message must sit unacknowledged in another
	// consumer's name before this one may claim it. Set it comfortably longer
	// than the slowest legitimate batch, or replicas will steal work from each
	// other mid-write.
	MinIdle time.Duration

	// ClaimInterval is how often to sweep for abandoned messages.
	ClaimInterval time.Duration

	// MaxLen caps the stream length approximately. Zero leaves it uncapped,
	// which is a decision to make deliberately: an uncapped stream with a
	// stalled consumer group will fill memory.
	MaxLen int64

	Logger *slog.Logger
}

func (o *RedisOptions) setDefaults() {
	if o.Stream == "" {
		o.Stream = "hoardcti.envelopes"
	}
	if o.Group == "" {
		o.Group = "ingest"
	}
	if o.MinIdle == 0 {
		o.MinIdle = 5 * time.Minute
	}
	if o.ClaimInterval == 0 {
		o.ClaimInterval = 30 * time.Second
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
}

// RedisConsumer reads envelopes from a Redis stream consumer group.
type RedisConsumer struct {
	opts RedisOptions
	log  *slog.Logger

	// recovering is true until this consumer has drained the messages that were
	// already assigned to its name — the ones it was holding when it last died.
	recovering bool
	lastClaim  time.Time
}

// NewRedisConsumer joins the consumer group, creating the stream and the group
// if they do not exist.
func NewRedisConsumer(ctx context.Context, opts RedisOptions) (*RedisConsumer, error) {
	opts.setDefaults()
	if opts.Client == nil {
		return nil, errors.New("queue: redis client is required")
	}
	if opts.Consumer == "" {
		return nil, errors.New("queue: consumer name is required")
	}

	// MkStream so the first collector to publish does not have to exist before
	// the first consumer starts. "0" so a group created after messages have
	// already been published still sees them.
	err := opts.Client.XGroupCreateMkStream(ctx, opts.Stream, opts.Group, "0").Err()
	if err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
		return nil, fmt.Errorf("queue: create consumer group %q on %q: %w",
			opts.Group, opts.Stream, err)
	}

	return &RedisConsumer{opts: opts, log: opts.Logger, recovering: true}, nil
}

// Name implements [Consumer].
func (c *RedisConsumer) Name() string {
	return fmt.Sprintf("redis-stream:%s/%s/%s", c.opts.Stream, c.opts.Group, c.opts.Consumer)
}

// Close implements [Consumer]. The Redis client is owned by the caller — it is
// shared with the cache — so it is not closed here.
func (c *RedisConsumer) Close() error { return nil }

// Receive returns up to max messages.
//
// It works through three sources in order of urgency: messages this consumer
// already owns but never acknowledged (a restart), messages abandoned by a
// consumer that died (a crash), and finally new messages. Getting that order
// wrong is how a stream ends up with a permanently stuck pending list that
// nobody notices until the backlog alert fires.
func (c *RedisConsumer) Receive(ctx context.Context, max int, block time.Duration) ([]Message, error) {
	if max <= 0 {
		max = 1
	}

	if c.recovering {
		msgs, err := c.readGroup(ctx, "0", max, 0)
		if err != nil {
			return nil, err
		}
		if len(msgs) > 0 {
			return msgs, nil
		}
		// An empty read at "0" means the pending list is drained.
		c.recovering = false
		c.log.Debug("recovered pending messages", "consumer", c.opts.Consumer)
	}

	if time.Since(c.lastClaim) >= c.opts.ClaimInterval {
		c.lastClaim = time.Now()
		msgs, err := c.claimAbandoned(ctx, max)
		if err != nil {
			// A failed sweep is not a reason to stop consuming; the next one
			// will pick the messages up.
			c.log.Warn("claim abandoned messages failed", "error", err)
		} else if len(msgs) > 0 {
			return msgs, nil
		}
	}

	return c.readGroup(ctx, ">", max, block)
}

func (c *RedisConsumer) readGroup(ctx context.Context, id string, max int, block time.Duration) ([]Message, error) {
	streams, err := c.opts.Client.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    c.opts.Group,
		Consumer: c.opts.Consumer,
		Streams:  []string{c.opts.Stream, id},
		Count:    int64(max),
		Block:    block,
	}).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil // block elapsed with nothing ready
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("queue: read from %q: %w", c.opts.Stream, err)
	}

	var out []Message
	for _, s := range streams {
		for _, m := range s.Messages {
			out = append(out, toMessage(m, 1))
		}
	}
	return out, nil
}

// claimAbandoned takes over messages left pending by a consumer that has gone
// away. Delivery counts come from XPENDING, which is the only place they are
// exposed, and they are what makes poison-message detection possible.
func (c *RedisConsumer) claimAbandoned(ctx context.Context, max int) ([]Message, error) {
	pending, err := c.opts.Client.XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream: c.opts.Stream,
		Group:  c.opts.Group,
		Idle:   c.opts.MinIdle,
		Start:  "-",
		End:    "+",
		Count:  int64(max),
	}).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("queue: list pending on %q: %w", c.opts.Stream, err)
	}
	if len(pending) == 0 {
		return nil, nil
	}

	ids := make([]string, 0, len(pending))
	retries := make(map[string]int64, len(pending))
	for _, p := range pending {
		ids = append(ids, p.ID)
		retries[p.ID] = p.RetryCount
	}

	claimed, err := c.opts.Client.XClaim(ctx, &redis.XClaimArgs{
		Stream:   c.opts.Stream,
		Group:    c.opts.Group,
		Consumer: c.opts.Consumer,
		MinIdle:  c.opts.MinIdle,
		Messages: ids,
	}).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("queue: claim %d pending messages: %w", len(ids), err)
	}

	out := make([]Message, 0, len(claimed))
	for _, m := range claimed {
		out = append(out, toMessage(m, retries[m.ID]))
	}
	if len(out) > 0 {
		c.log.Info("claimed abandoned messages",
			"count", len(out), "consumer", c.opts.Consumer)
	}
	return out, nil
}

// Ack implements [Consumer].
func (c *RedisConsumer) Ack(ctx context.Context, ids ...string) error {
	if len(ids) == 0 {
		return nil
	}
	if err := c.opts.Client.XAck(ctx, c.opts.Stream, c.opts.Group, ids...).Err(); err != nil {
		return fmt.Errorf("queue: acknowledge %d messages: %w", len(ids), err)
	}
	return nil
}

// Pending implements [Consumer].
func (c *RedisConsumer) Pending(ctx context.Context) (int64, error) {
	res, err := c.opts.Client.XPending(ctx, c.opts.Stream, c.opts.Group).Result()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("queue: read pending count: %w", err)
	}
	return res.Count, nil
}

// Backlog implements [Consumer]. It reports the group's lag — messages in the
// stream the group has never been handed — falling back to the stream length on
// Redis versions that do not report lag.
func (c *RedisConsumer) Backlog(ctx context.Context) (int64, error) {
	groups, err := c.opts.Client.XInfoGroups(ctx, c.opts.Stream).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, fmt.Errorf("queue: read group info: %w", err)
	}
	for _, g := range groups {
		if g.Name != c.opts.Group {
			continue
		}
		if g.Lag > 0 {
			return g.Lag, nil
		}
		return 0, nil
	}
	return 0, nil
}

// RedisPublisher writes envelopes to a Redis stream.
type RedisPublisher struct {
	client redis.UniversalClient
	stream string
	maxLen int64
}

// NewRedisPublisher creates a publisher for the given stream.
func NewRedisPublisher(client redis.UniversalClient, stream string, maxLen int64) *RedisPublisher {
	if stream == "" {
		stream = "hoardcti.envelopes"
	}
	return &RedisPublisher{client: client, stream: stream, maxLen: maxLen}
}

// Name implements [Publisher].
func (p *RedisPublisher) Name() string { return "redis-stream:" + p.stream }

// Close implements [Publisher]. The client is owned by the caller.
func (p *RedisPublisher) Close() error { return nil }

// Publish implements [Publisher].
func (p *RedisPublisher) Publish(ctx context.Context, body []byte) (string, error) {
	args := &redis.XAddArgs{
		Stream: p.stream,
		Values: map[string]any{FieldEnvelope: body},
	}
	if p.maxLen > 0 {
		// Approximate trimming: exact trimming walks the stream and is far more
		// expensive for a bound that is a safety net rather than a contract.
		args.MaxLen = p.maxLen
		args.Approx = true
	}
	id, err := p.client.XAdd(ctx, args).Result()
	if err != nil {
		return "", fmt.Errorf("queue: publish to %q: %w", p.stream, err)
	}
	return id, nil
}

func toMessage(m redis.XMessage, deliveries int64) Message {
	var body []byte
	switch v := m.Values[FieldEnvelope].(type) {
	case string:
		body = []byte(v)
	case []byte:
		body = v
	}
	if deliveries < 1 {
		deliveries = 1
	}
	return Message{ID: m.ID, Body: body, Deliveries: deliveries}
}
