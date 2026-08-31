package store

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// partitionCache remembers which sighting partitions this process has already
// provisioned, so a steady stream of batches costs one round trip per month
// rather than one per batch.
type partitionCache struct {
	mu sync.Mutex
	m  map[string]struct{}
}

func newPartitionCache() *partitionCache {
	return &partitionCache{m: make(map[string]struct{})}
}

func (c *partitionCache) has(month string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.m[month]
	return ok
}

func (c *partitionCache) add(month string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[month] = struct{}{}
}

// monthKey is the partition identity for a timestamp, computed in UTC to match
// ensure_sighting_partition().
func monthKey(t time.Time) string { return t.UTC().Format("2006_01") }

// ensureSightingPartitions provisions whatever partitions this batch needs.
//
// Called before the ingest transaction opens, never inside it: creating a
// partition takes ACCESS EXCLUSIVE on the parent table, and taking that lock in
// the same transaction as a bulk COPY would block every reader of sighting for
// the length of the load.
func (s *Store) ensureSightingPartitions(ctx context.Context, b *Batch) error {
	months := make(map[string]time.Time)
	for i := range b.Records {
		if b.Records[i].Sighting == nil {
			continue
		}
		t := b.Records[i].Sighting.ObservedAt
		if k := monthKey(t); !s.partitions.has(k) {
			months[k] = t
		}
	}
	for _, t := range months {
		if err := s.EnsureSightingPartition(ctx, t); err != nil {
			return err
		}
	}
	return nil
}

// EnsureSightingPartition creates the monthly partition covering t if it is
// missing. Safe to call concurrently and from several processes.
func (s *Store) EnsureSightingPartition(ctx context.Context, t time.Time) error {
	var name string
	if err := s.pool.QueryRow(ctx,
		`SELECT ensure_sighting_partition($1)`, t.UTC()).Scan(&name); err != nil {
		return fmt.Errorf("ensure sighting partition for %s: %w", t.UTC().Format("2006-01"), err)
	}
	s.partitions.add(monthKey(t))
	return nil
}

// EnsureSightingPartitionsAhead provisions the current month plus the next
// `ahead` months. Run it on a schedule: a partition that does not exist when the
// month turns over sends every sighting into sighting_default, and rows sitting
// there block the creation of the partition that should have held them.
func (s *Store) EnsureSightingPartitionsAhead(ctx context.Context, ahead int) ([]string, error) {
	now := time.Now().UTC()
	created := make([]string, 0, ahead+1)
	for i := 0; i <= ahead; i++ {
		t := now.AddDate(0, i, 0)
		if err := s.EnsureSightingPartition(ctx, t); err != nil {
			return created, err
		}
		created = append(created, "sighting_"+monthKey(t))
	}
	return created, nil
}

// DropSightingPartitionsBefore applies retention by dropping whole partitions.
// Returns the names it dropped.
//
// Dropping a partition is a catalogue operation; DELETE on the same data would
// rewrite hundreds of millions of rows and leave the table needing a vacuum.
func (s *Store) DropSightingPartitionsBefore(ctx context.Context, cutoff time.Time) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT drop_sighting_partitions_before($1)`, cutoff.UTC())
	if err != nil {
		return nil, fmt.Errorf("drop sighting partitions before %s: %w",
			cutoff.UTC().Format(time.RFC3339), err)
	}
	defer rows.Close()

	var dropped []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan dropped partition: %w", err)
		}
		dropped = append(dropped, name)
	}
	return dropped, rows.Err()
}

// DefaultPartitionRows counts what has landed in sighting_default.
//
// It should always be zero. Anything in there arrived when the partition it
// belonged in did not exist, and — worse — its presence will make creating that
// partition fail, because Postgres validates the default partition's contents
// against every new range. Non-zero means: detach the default, create the
// missing partitions, move the rows, reattach.
func (s *Store) DefaultPartitionRows(ctx context.Context) (int64, error) {
	var n int64
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM sighting_default`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count sighting_default: %w", err)
	}
	return n, nil
}

// DeadLetter parks an envelope that could not be processed.
//
// A poison message must not be able to stall a consumer group forever, so it is
// recorded here with its payload and reason, acknowledged on the queue, and
// dealt with out of band.
func (s *Store) DeadLetter(ctx context.Context, sourceSlug, messageID, stage, reason string, payload []byte) error {
	// The payload has to be valid JSON to land in a jsonb column, and the whole
	// reason we are here may be that it is not. Wrap anything unparseable as a
	// string so the evidence survives.
	if !isJSON(payload) {
		payload = jsonString(string(payload))
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ingest_dead_letter (source_slug, message_id, stage, reason, payload)
		VALUES (NULLIF($1, ''), NULLIF($2, ''), $3, $4, $5)`,
		sourceSlug, messageID, stage, truncateReason(reason), payload)
	if err != nil {
		return fmt.Errorf("record dead letter: %w", err)
	}
	return nil
}

// maxReasonLen keeps a pathological error — a validation failure listing ten
// thousand bad records — from becoming the largest row in the database.
const maxReasonLen = 8192

func truncateReason(s string) string {
	if len(s) <= maxReasonLen {
		return s
	}
	return s[:maxReasonLen] + "… (truncated)"
}
