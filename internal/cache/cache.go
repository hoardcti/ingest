// Package cache maintains the "is this IOC known?" lookup.
//
// That question is asked at a completely different rate from everything else in
// the system — it is the one query that sits in front of a detection pipeline —
// and Postgres should not be answering it. The ingest service writes through to
// Redis as it writes to Postgres, so the cache is a projection of the database
// rather than a second source of truth: losing the whole keyspace costs a
// rebuild, not data.
package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// KeyPrefix namespaces every key this package writes.
const KeyPrefix = "hoardcti:ioc:"

// Verdict is what the cache knows about one indicator.
//
// It carries the entity id so a caller that needs the full record can go
// straight to Postgres by primary key, and enough summary for the common case
// where it does not need to.
type Verdict struct {
	EntityID  string    `json:"entity_id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	// Sources that have reported this indicator, most recent last.
	Sources []string `json:"sources,omitempty"`

	Tags       []string `json:"tags,omitempty"`
	Confidence *float64 `json:"confidence,omitempty"`
}

// Cache is the indicator lookup projection.
type Cache interface {
	// Upsert merges verdicts into the cache. Called on the ingest path, so it
	// must not fail the write when Redis is unavailable — see [Redis.Upsert].
	Upsert(ctx context.Context, verdicts []Verdict, ttl time.Duration) error

	// Lookup answers "is this IOC known?".
	Lookup(ctx context.Context, typ, value string) (Verdict, bool, error)

	// Ping reports whether the cache is reachable.
	Ping(ctx context.Context) error

	// Name identifies the backend in logs and health output.
	Name() string
}

// Key builds the cache key for an indicator.
func Key(typ, value string) string { return KeyPrefix + typ + ":" + value }

// Noop is the cache used when none is configured. Lookups always miss.
type Noop struct{}

// Upsert implements [Cache].
func (Noop) Upsert(context.Context, []Verdict, time.Duration) error { return nil }

// Lookup implements [Cache].
func (Noop) Lookup(context.Context, string, string) (Verdict, bool, error) {
	return Verdict{}, false, nil
}

// Ping implements [Cache].
func (Noop) Ping(context.Context) error { return nil }

// Name implements [Cache].
func (Noop) Name() string { return "none" }

// Redis is a Redis- or Valkey-backed [Cache].
type Redis struct {
	client redis.UniversalClient
	addr   string
}

// NewRedis wraps an existing client. The client is not closed by this package;
// it is usually shared with the queue.
func NewRedis(client redis.UniversalClient, addr string) *Redis {
	return &Redis{client: client, addr: addr}
}

// Name implements [Cache].
func (c *Redis) Name() string { return "redis://" + c.addr }

// Ping implements [Cache].
func (c *Redis) Ping(ctx context.Context) error {
	if err := c.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("ping cache: %w", err)
	}
	return nil
}

// Upsert merges verdicts into the cache, one pipelined round trip for the whole
// batch.
//
// Merging rather than overwriting matters: two feeds reporting the same
// indicator each know a fraction of the truth, and a blind SET would make the
// cached verdict depend on which envelope arrived last.
func (c *Redis) Upsert(ctx context.Context, verdicts []Verdict, ttl time.Duration) error {
	if len(verdicts) == 0 {
		return nil
	}

	// Read the existing entries first so the merge has something to merge with.
	keys := make([]string, len(verdicts))
	for i, v := range verdicts {
		keys[i] = Key(v.Type, v.Value)
	}
	existing, err := c.client.MGet(ctx, keys...).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("read cache entries: %w", err)
	}

	pipe := c.client.Pipeline()
	for i, v := range verdicts {
		merged := v
		if i < len(existing) {
			if s, ok := existing[i].(string); ok {
				var prev Verdict
				if json.Unmarshal([]byte(s), &prev) == nil {
					merged = merge(prev, v)
				}
			}
		}
		b, err := json.Marshal(merged)
		if err != nil {
			return fmt.Errorf("encode verdict for %s: %w", keys[i], err)
		}
		pipe.Set(ctx, keys[i], b, ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("write %d cache entries: %w", len(verdicts), err)
	}
	return nil
}

// Lookup implements [Cache].
func (c *Redis) Lookup(ctx context.Context, typ, value string) (Verdict, bool, error) {
	b, err := c.client.Get(ctx, Key(typ, value)).Bytes()
	if errors.Is(err, redis.Nil) {
		return Verdict{}, false, nil
	}
	if err != nil {
		return Verdict{}, false, fmt.Errorf("cache lookup: %w", err)
	}
	var v Verdict
	if err := json.Unmarshal(b, &v); err != nil {
		// A corrupt entry is a cache miss, not an outage. The next ingest of
		// this indicator overwrites it.
		return Verdict{}, false, nil
	}
	return v, true, nil
}

// merge folds a new observation into what the cache already held.
func merge(prev, next Verdict) Verdict {
	out := next
	if !prev.FirstSeen.IsZero() && (out.FirstSeen.IsZero() || prev.FirstSeen.Before(out.FirstSeen)) {
		out.FirstSeen = prev.FirstSeen
	}
	if prev.LastSeen.After(out.LastSeen) {
		out.LastSeen = prev.LastSeen
	}
	out.Sources = union(prev.Sources, next.Sources, 32)
	out.Tags = union(prev.Tags, next.Tags, 64)
	if out.Confidence == nil {
		out.Confidence = prev.Confidence
	} else if prev.Confidence != nil && *prev.Confidence > *out.Confidence {
		// Keep the strongest assertion any source has made. A feed that omits
		// confidence is not asserting doubt.
		out.Confidence = prev.Confidence
	}
	return out
}

// union appends without duplicating, keeping the most recent entries when the
// result would exceed limit. An indicator seen by two hundred feeds does not
// need two hundred names in a cache entry.
func union(a, b []string, limit int) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, s := range list {
			if s == "" {
				continue
			}
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}
