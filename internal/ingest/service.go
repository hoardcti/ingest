// Package ingest is the single writer.
//
// Everything that turns a collector's report into database rows happens here
// and nowhere else: archive the raw payload, canonicalise every value, write one
// transaction, project the result into the lookup cache. Scrapers hold no
// database credentials and know nothing of the schema, which is what keeps
// three languages' worth of collectors from developing three subtly different
// ideas of what a normalised hash looks like.
package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/hoardcti/ingest/internal/archive"
	"github.com/hoardcti/ingest/internal/cache"
	"github.com/hoardcti/ingest/internal/envelope"
	"github.com/hoardcti/ingest/internal/store"
	"github.com/hoardcti/ingest/internal/telemetry"
)

// Options configure a [Service].
type Options struct {
	// CacheTTL is how long a cached verdict survives without being refreshed.
	// It should be comfortably longer than the slowest feed's collection
	// interval, or indicators will fall out of the cache between collections.
	CacheTTL time.Duration

	// MaxDropRatio is the proportion of records that may fail canonicalisation
	// before the whole envelope is treated as bad. A handful of malformed lines
	// in a feed is normal; a third of them means the format changed and
	// ingesting the remainder would quietly lose data.
	MaxDropRatio float64

	Logger  *slog.Logger
	Metrics *telemetry.Metrics
}

func (o *Options) setDefaults() {
	if o.CacheTTL == 0 {
		o.CacheTTL = 30 * 24 * time.Hour
	}
	if o.MaxDropRatio == 0 {
		o.MaxDropRatio = 0.25
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
}

// Service processes envelopes. It is safe for concurrent use.
type Service struct {
	store   *store.Store
	archive archive.Archiver
	cache   cache.Cache
	opts    Options
	log     *slog.Logger
}

// New builds the ingest service. A nil archive or cache is replaced with the
// no-op implementation, so both are genuinely optional.
func New(st *store.Store, ar archive.Archiver, ca cache.Cache, opts Options) *Service {
	opts.setDefaults()
	if ar == nil {
		ar = archive.Noop{}
	}
	if ca == nil {
		ca = cache.Noop{}
	}
	return &Service{store: st, archive: ar, cache: ca, opts: opts, log: opts.Logger}
}

// Result describes what one envelope did.
type Result struct {
	Source    string
	Digest    string
	Duplicate bool

	RecordsIn      int
	RecordsWritten int
	RecordsDropped int

	Indicators    int
	CVEs          int
	Breaches      int
	Sightings     int
	Relationships int
	Entities      int

	Elapsed time.Duration
}

// Process handles one envelope, from raw transport bytes to committed rows.
//
// A returned error is either a [PermanentError], meaning the envelope should be
// dead-lettered and acknowledged, or a transient one, meaning the message
// should be left unacknowledged for redelivery. Callers must respect that
// distinction — see the comment on [PermanentError].
func (s *Service) Process(ctx context.Context, raw []byte) (Result, error) {
	start := time.Now()
	digest := Digest(raw)
	res := Result{Digest: digest}

	e, err := envelope.Decode(raw)
	if err != nil {
		return res, Permanent(StageDecode, err)
	}
	res.Source = e.Source
	res.RecordsIn = len(e.Records)

	if err := envelope.Validate(e); err != nil {
		return res, Permanent(StageValidate, err)
	}

	if err := s.archiveRaw(ctx, e); err != nil {
		// Archival failing is an outage, not bad data: retry rather than lose
		// the only copy of a payload we may not be able to fetch again.
		return res, err
	}

	built := build(e, digest)
	batch := built.Batch
	res.RecordsDropped = len(built.Dropped)
	s.reportDropped(e.Source, built.Dropped)

	if drops := built.RecordDrops(); drops > 0 && len(e.Records) > 0 {
		ratio := float64(drops) / float64(len(e.Records))
		if ratio > s.opts.MaxDropRatio {
			return res, Permanent(StageCanonicalise, fmt.Errorf(
				"%d of %d records failed canonicalisation (%.0f%%, limit %.0f%%); "+
					"the feed format has probably changed: %v",
				drops, len(e.Records), ratio*100,
				s.opts.MaxDropRatio*100, firstErrors(built.Dropped, 3)))
		}
	}
	if len(batch.Records) == 0 && len(batch.Relationships) == 0 {
		return res, Permanent(StageCanonicalise,
			fmt.Errorf("no records survived canonicalisation: %v", firstErrors(built.Dropped, 3)))
	}

	wr, err := s.store.WriteBatch(ctx, batch)
	if err != nil {
		return res, classifyWriteError(err)
	}

	res.Duplicate = wr.Duplicate
	res.Entities = len(wr.Entities)
	res.Indicators = wr.Indicators
	res.CVEs = wr.CVEs
	res.Breaches = wr.Breaches
	res.Sightings = wr.Sightings
	res.Relationships = wr.Relationships
	res.RecordsWritten = len(batch.Records)
	res.Elapsed = time.Since(start)

	if wr.Duplicate {
		// Nothing was written, so nothing is reported as written. RecordsIn
		// still says how big the envelope was; conflating the two would have
		// the action's `records` output — and anyone reading it — believe a
		// replay ingested everything a second time.
		res.RecordsWritten = 0

		s.opts.Metrics.ObserveEnvelope(e.Source, telemetry.OutcomeDuplicate)
		s.log.Debug("envelope already processed",
			"source", e.Source, "digest", digest, "records", len(e.Records))
		return res, nil
	}

	s.opts.Metrics.ObserveEnvelope(e.Source, telemetry.OutcomeWritten)
	s.opts.Metrics.ObserveRecords(e.Source, string(envelope.KindIndicator), wr.Indicators)
	s.opts.Metrics.ObserveRecords(e.Source, string(envelope.KindCVE), wr.CVEs)
	s.opts.Metrics.ObserveRecords(e.Source, string(envelope.KindBreach), wr.Breaches)
	s.opts.Metrics.ObserveWrite(e.Source, len(batch.Records), wr.Sightings, wr.Elapsed.Seconds())

	// The cache is a projection of Postgres, not a second source of truth, so a
	// failure here is logged and counted but never fails the ingest. Losing the
	// keyspace costs a rebuild; failing the write would cost the data.
	s.refreshCache(ctx, e, built, wr)

	return res, nil
}

// archiveRaw stores an inline payload and fills in the reference and content
// hash the collector did not supply.
func (s *Service) archiveRaw(ctx context.Context, e *envelope.Envelope) error {
	if e.Raw == nil {
		return nil
	}
	data, err := e.Raw.Bytes()
	if err != nil {
		return Permanent(StageArchive, err)
	}
	if e.ContentHash == "" {
		e.ContentHash = archive.Hash(data)
	}

	ref, err := s.archive.Put(ctx, data, e.Raw.ContentType())
	if err != nil {
		return fmt.Errorf("archive raw payload for %s: %w", e.Source, err)
	}
	if ref != "" && e.RawRef == "" {
		e.RawRef = ref
	}
	s.opts.Metrics.ObserveArchive(len(data))

	// The payload is safely in the archive and would otherwise be carried
	// through canonicalisation and into every log line about this envelope.
	e.Raw = nil
	return nil
}

// refreshCache projects the batch's indicators into the lookup cache.
func (s *Service) refreshCache(ctx context.Context, e *envelope.Envelope, built *buildResult, wr store.WriteResult) {
	if _, isNoop := s.cache.(cache.Noop); isNoop {
		return
	}

	ids := make(map[string]string, len(wr.Entities))
	for _, ref := range wr.Entities {
		if ref.Kind == string(envelope.KindIndicator) {
			ids[ref.CanonicalKey] = ref.ID
		}
	}
	if len(ids) == 0 {
		return
	}

	b := built.Batch
	verdicts := make([]cache.Verdict, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for i := range b.Records {
		r := &b.Records[i]
		if r.Indicator == nil {
			continue
		}
		id, ok := ids[r.Entity.CanonicalKey]
		if !ok {
			continue
		}
		if _, dup := seen[r.Entity.CanonicalKey]; dup {
			continue
		}
		seen[r.Entity.CanonicalKey] = struct{}{}

		v := cache.Verdict{
			EntityID:  id,
			Type:      r.Indicator.Type,
			Value:     r.Indicator.Value,
			FirstSeen: r.Entity.FirstSeen,
			LastSeen:  r.Entity.LastSeen,
			Sources:   []string{e.Source},
		}
		if i < len(built.Contexts) && built.Contexts[i] != nil {
			v.Tags = built.Contexts[i].Tags
			v.Confidence = built.Contexts[i].Confidence
		}
		verdicts = append(verdicts, v)
	}

	if err := s.cache.Upsert(ctx, verdicts, s.opts.CacheTTL); err != nil {
		s.opts.Metrics.ObserveCacheFailure()
		s.log.Warn("cache write-through failed; lookups will be stale until the "+
			"next sighting of these indicators",
			"source", e.Source, "indicators", len(verdicts), "error", err)
	}
}

func (s *Service) reportDropped(source string, dropped []droppedRecord) {
	if len(dropped) == 0 {
		return
	}
	byReason := make(map[string]int, 4)
	for _, d := range dropped {
		byReason[d.Reason]++
	}
	for reason, n := range byReason {
		s.opts.Metrics.ObserveDropped(source, reason, n)
	}
	s.log.Warn("dropped records during canonicalisation",
		"source", source,
		"count", len(dropped),
		"reasons", byReason,
		"examples", firstErrors(dropped, 3))
}

// Digest is the idempotency key for a delivered message: the SHA-256 of exactly
// the bytes that arrived.
func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Store exposes the underlying store, for the dead-letter path and health
// checks.
func (s *Service) Store() *store.Store { return s.store }

// Archive exposes the configured archive backend.
func (s *Service) Archive() archive.Archiver { return s.archive }

// Cache exposes the configured cache backend.
func (s *Service) Cache() cache.Cache { return s.cache }

func firstErrors(dropped []droppedRecord, n int) []string {
	if len(dropped) < n {
		n = len(dropped)
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("record %d: %v", dropped[i].Index, dropped[i].Err))
	}
	return out
}
