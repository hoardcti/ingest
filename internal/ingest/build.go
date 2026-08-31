package ingest

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hoardcti/ingest/internal/canonical"
	"github.com/hoardcti/ingest/internal/envelope"
	"github.com/hoardcti/ingest/internal/store"
)

// DropReason categorises why a record did not make it into the batch. It is a
// metric label, so it must stay a small closed set — the detail goes in the log
// line, not here.
const (
	DropCanonicalise = "canonicalise"
	DropMissing      = "missing_payload"
	DropUnknownKind  = "unknown_kind"
)

// droppedRecord is one record or relationship that could not be canonicalised.
type droppedRecord struct {
	Index          int
	Reason         string
	Err            error
	IsRelationship bool
}

// buildResult is what canonicalising an envelope produced.
type buildResult struct {
	Batch *store.Batch

	// Contexts runs parallel to Batch.Records, holding each surviving record's
	// merged context. The cache projection needs the tags and confidence, and
	// carrying them here is cheaper than decoding the sighting JSON back out.
	Contexts []*envelope.Context

	Dropped []droppedRecord
}

// RecordDrops counts only the records that were discarded, not relationships.
// The drop ratio is a statement about the feed's record format.
func (r *buildResult) RecordDrops() int {
	n := 0
	for _, d := range r.Dropped {
		if !d.IsRelationship {
			n++
		}
	}
	return n
}

// build turns a validated envelope into a batch of already-canonical rows.
//
// Individual records are allowed to fail. A feed of fifty thousand indicators
// with four malformed lines should load forty-nine thousand nine hundred and
// ninety-six of them and tell you about the four, not reject the lot — but a
// feed where a third of the records fail has changed format, and the caller
// turns that into a hard failure rather than quietly ingesting the remains.
func build(e *envelope.Envelope, digest string) *buildResult {
	b := &store.Batch{
		SourceSlug:     e.Source,
		SchemaVersion:  e.SchemaVersion,
		SourceRunID:    e.SourceRunID,
		EnvelopeDigest: digest,
		ContentHash:    e.ContentHash,
		RawRef:         e.RawRef,
		CollectedAt:    e.CollectedAt,
		Records:        make([]store.Record, 0, len(e.Records)),
	}
	out := &buildResult{
		Batch:    b,
		Contexts: make([]*envelope.Context, 0, len(e.Records)),
	}

	for i := range e.Records {
		r := &e.Records[i]
		observedAt := r.EffectiveObservedAt(e.CollectedAt)
		ctxt := e.EffectiveContext(r)

		rec, reason, err := buildRecord(r, observedAt, ctxt, e)
		if err != nil {
			out.Dropped = append(out.Dropped, droppedRecord{Index: i, Reason: reason, Err: err})
			continue
		}
		b.Records = append(b.Records, rec)
		out.Contexts = append(out.Contexts, ctxt)
	}

	for i := range e.Relationships {
		r := &e.Relationships[i]
		rel, err := buildRelationship(r, e.CollectedAt)
		if err != nil {
			out.Dropped = append(out.Dropped, droppedRecord{
				Index:          i,
				Reason:         DropCanonicalise,
				Err:            fmt.Errorf("relationship: %w", err),
				IsRelationship: true,
			})
			continue
		}
		b.Relationships = append(b.Relationships, rel)
	}

	out.addEndpointRecords(e)
	return out
}

// addEndpointRecords gives relationship endpoints their module rows.
//
// Without this an endpoint gets an `entity` row and nothing else, which breaks
// the invariant that a module table extends `entity` one-to-one — and, more
// practically, makes the endpoint invisible to `SELECT … FROM indicator WHERE
// value = ?`. An indicator a feed says exploits Log4Shell is a real indicator
// and has to be findable by its value.
//
// The rows carry no Sighting: the source asserted an edge, not an observation.
// And only where the payload can be filled in losslessly — a `breach` endpoint
// gives us a slug but `breach.name` is NOT NULL, and inventing a name would be
// worse than leaving the entity bare until a real breach record arrives.
func (r *buildResult) addEndpointRecords(e *envelope.Envelope) {
	described := make(map[[2]string]struct{}, len(r.Batch.Records))
	for i := range r.Batch.Records {
		rec := &r.Batch.Records[i]
		described[[2]string{rec.Entity.Kind, rec.Entity.CanonicalKey}] = struct{}{}
	}

	add := func(kind, key string, typ envelope.ObservableType, first, last time.Time) {
		id := [2]string{kind, key}
		if _, ok := described[id]; ok {
			return
		}
		described[id] = struct{}{}

		rec := store.Record{
			Entity: store.Entity{
				Kind: kind, CanonicalKey: key, FirstSeen: first, LastSeen: last,
			},
		}
		switch envelope.Kind(kind) {
		case envelope.KindIndicator:
			// RawValue is left empty on purpose: the upsert COALESCEs it, so a
			// real record's provenance is never overwritten by an endpoint.
			rec.Indicator = &store.IndicatorFields{Type: string(typ), Value: key}
		case envelope.KindCVE:
			rec.CVE = &store.CVEFields{CVEID: key}
		default:
			return
		}

		r.Batch.Records = append(r.Batch.Records, rec)
		r.Contexts = append(r.Contexts, nil)
	}

	for i := range r.Batch.Relationships {
		rel := &r.Batch.Relationships[i]
		add(rel.SourceKind, rel.SourceKey, envelope.ObservableType(rel.SourceType), rel.FirstSeen, rel.LastSeen)
		add(rel.TargetKind, rel.TargetKey, envelope.ObservableType(rel.TargetType), rel.FirstSeen, rel.LastSeen)
	}
}

func buildRecord(r *envelope.Record, observedAt time.Time, c *envelope.Context, e *envelope.Envelope) (store.Record, string, error) {
	first, last := seenWindow(c, observedAt)

	rec := store.Record{
		Entity: store.Entity{
			Kind:      string(r.Kind),
			FirstSeen: first,
			LastSeen:  last,
		},
		Sighting: &store.Sighting{
			ObservedAt:  observedAt,
			ContentHash: nullable(e.ContentHash),
			RawRef:      nullable(e.RawRef),
			Context:     encodeContext(c),
		},
	}

	switch r.Kind {
	case envelope.KindIndicator:
		if r.Indicator == nil {
			return rec, DropMissing, fmt.Errorf("kind is indicator but no indicator payload")
		}
		obs, err := canonical.Indicator(r.Indicator.Type, r.Indicator.RawValue)
		if err != nil {
			return rec, DropCanonicalise, err
		}
		rec.Entity.CanonicalKey = obs.Value
		rec.Indicator = &store.IndicatorFields{
			Type:     string(obs.Type),
			Value:    obs.Value,
			RawValue: r.Indicator.RawValue,
		}

	case envelope.KindCVE:
		if r.CVE == nil {
			return rec, DropMissing, fmt.Errorf("kind is cve but no cve payload")
		}
		id, err := canonical.CVEID(r.CVE.CVEID)
		if err != nil {
			return rec, DropCanonicalise, err
		}
		rec.Entity.CanonicalKey = id
		rec.CVE = &store.CVEFields{
			CVEID:          id,
			Summary:        nullable(r.CVE.Summary),
			CVSSScore:      r.CVE.CVSSScore,
			CVSSVector:     nullable(r.CVE.CVSSVector),
			Severity:       nullableLower(r.CVE.Severity),
			EPSSScore:      r.CVE.EPSSScore,
			KnownExploited: r.CVE.KnownExploited != nil && *r.CVE.KnownExploited,
			CWE:            r.CVE.CWE,
			PublishedAt:    r.CVE.PublishedAt,
			ModifiedAt:     r.CVE.ModifiedAt,
			Refs:           r.CVE.Refs,
		}

	case envelope.KindBreach:
		if r.Breach == nil {
			return rec, DropMissing, fmt.Errorf("kind is breach but no breach payload")
		}
		slug, err := canonical.BreachSlug(r.Breach)
		if err != nil {
			return rec, DropCanonicalise, err
		}
		rec.Entity.CanonicalKey = slug
		rec.Breach = &store.BreachFields{
			Slug:        slug,
			Name:        r.Breach.Name,
			Domain:      canonicalDomain(r.Breach.Domain),
			Description: nullable(r.Breach.Description),
			BreachDate:  breachDate(r.Breach.BreachDate),
			DisclosedAt: r.Breach.DisclosedAt,
			RecordCount: r.Breach.RecordCount,
			DataClasses: r.Breach.DataClasses,
			Verified:    r.Breach.Verified != nil && *r.Breach.Verified,
		}

	default:
		return rec, DropUnknownKind, fmt.Errorf("unknown kind %q", r.Kind)
	}

	return rec, "", nil
}

func buildRelationship(r *envelope.Relationship, collectedAt time.Time) (store.Relationship, error) {
	srcKind, srcKey, srcType, err := canonical.Key(r.Source)
	if err != nil {
		return store.Relationship{}, fmt.Errorf("source endpoint: %w", err)
	}
	dstKind, dstKey, dstType, err := canonical.Key(r.Target)
	if err != nil {
		return store.Relationship{}, fmt.Errorf("target endpoint: %w", err)
	}

	first, last := collectedAt, collectedAt
	if r.FirstSeen != nil && !r.FirstSeen.IsZero() {
		first = *r.FirstSeen
	}
	if r.LastSeen != nil && !r.LastSeen.IsZero() {
		last = *r.LastSeen
	}
	if last.Before(first) {
		first, last = last, first
	}

	rel := store.Relationship{
		SourceKind: string(srcKind),
		SourceKey:  srcKey,
		SourceType: string(srcType),
		TargetKind: string(dstKind),
		TargetKey:  dstKey,
		TargetType: string(dstType),
		Type:       string(r.Type),
		Confidence: r.Confidence,
		FirstSeen:  first,
		LastSeen:   last,
	}
	if len(r.Metadata) > 0 {
		if b, err := json.Marshal(r.Metadata); err == nil {
			rel.Metadata = b
		}
	}
	return rel, nil
}

// seenWindow derives the entity's first/last seen from what the source claimed,
// falling back to when we observed it.
//
// A source's first_seen is clamped to no later than the observation itself: a
// feed cannot have first seen something after it told us about it, and letting
// a bad value through would poison entity.first_seen for every other source.
func seenWindow(c *envelope.Context, observedAt time.Time) (first, last time.Time) {
	first, last = observedAt, observedAt
	if c == nil {
		return first, last
	}
	if c.FirstSeen != nil && !c.FirstSeen.IsZero() && c.FirstSeen.Before(first) {
		first = *c.FirstSeen
	}
	if c.LastSeen != nil && !c.LastSeen.IsZero() && c.LastSeen.After(last) {
		last = *c.LastSeen
	}
	return first, last
}

// encodeContext serialises the sighting context. Returns nil for an empty
// context so the column stays NULL rather than holding an empty object.
func encodeContext(c *envelope.Context) []byte {
	if c == nil {
		return nil
	}
	if c.FirstSeen == nil && c.LastSeen == nil && c.Confidence == nil &&
		len(c.Tags) == 0 && c.TLP == "" && len(c.Attributes) == 0 {
		return nil
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	return b
}

// canonicalDomain normalises a breach's domain through the same path an
// indicator would take, so that "Example.COM" on a breach and "example.com" as
// an indicator can be joined. A domain that will not canonicalise is dropped
// rather than failing the breach — it is a descriptive field, not the identity.
func canonicalDomain(d string) *string {
	if d == "" {
		return nil
	}
	obs, err := canonical.Indicator(envelope.TypeDomain, d)
	if err != nil {
		return nullable(d)
	}
	return &obs.Value
}

func breachDate(d *envelope.Date) *time.Time {
	if d == nil || d.IsZero() {
		return nil
	}
	t := d.Time
	return &t
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nullableLower(s string) *string {
	if s == "" {
		return nil
	}
	l := lower(s)
	return &l
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
