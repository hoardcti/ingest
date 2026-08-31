package ingest

import (
	"encoding/json"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/hoardcti/ingest/internal/envelope"
	"github.com/hoardcti/ingest/internal/store"
)

var collected = time.Date(2026, 8, 31, 6, 0, 0, 0, time.UTC)

func env(records ...envelope.Record) *envelope.Envelope {
	return &envelope.Envelope{
		SchemaVersion: envelope.SchemaVersion,
		Source:        "test-feed",
		CollectedAt:   collected,
		Records:       records,
	}
}

func indicatorRecord(typ envelope.ObservableType, raw string) envelope.Record {
	return envelope.Record{
		Kind:      envelope.KindIndicator,
		Indicator: &envelope.Indicator{Type: typ, RawValue: raw},
	}
}

func TestBuildCanonicalisesIndicators(t *testing.T) {
	e := env(
		indicatorRecord(envelope.TypeAuto, "hxxp://EVIL[.]com:80/a/./b"),
		indicatorRecord(envelope.TypeAuto, "185[.]234[.]1[.]7"),
	)

	got := build(e, "digest")
	if len(got.Batch.Records) != 2 {
		t.Fatalf("records = %d, want 2 (dropped: %v)", len(got.Batch.Records), got.Dropped)
	}

	first := got.Batch.Records[0]
	if first.Entity.CanonicalKey != "http://evil.com/a/b" {
		t.Errorf("canonical key = %q, want %q", first.Entity.CanonicalKey, "http://evil.com/a/b")
	}
	if first.Indicator.Type != string(envelope.TypeURL) {
		t.Errorf("type = %q, want url", first.Indicator.Type)
	}
	// The raw value is provenance and must survive verbatim.
	if first.Indicator.RawValue != "hxxp://EVIL[.]com:80/a/./b" {
		t.Errorf("raw_value = %q, want the original spelling", first.Indicator.RawValue)
	}
	if first.Entity.CanonicalKey != first.Indicator.Value {
		t.Errorf("entity key %q and indicator value %q must be the same string",
			first.Entity.CanonicalKey, first.Indicator.Value)
	}
}

// A handful of malformed lines in a feed of thousands is normal, and must not
// take the good records down with them.
func TestBuildDropsOnlyBadRecords(t *testing.T) {
	e := env(
		indicatorRecord(envelope.TypeAuto, "evil.com"),
		indicatorRecord(envelope.TypeIPv4, "not-an-ip"),
		indicatorRecord(envelope.TypeAuto, "185.234.1.7"),
		indicatorRecord(envelope.TypeMD5, "tooshort"),
	)

	got := build(e, "digest")

	if len(got.Batch.Records) != 2 {
		t.Errorf("kept %d records, want 2", len(got.Batch.Records))
	}
	if got.RecordDrops() != 2 {
		t.Errorf("RecordDrops() = %d, want 2", got.RecordDrops())
	}
	for _, d := range got.Dropped {
		if d.Reason != DropCanonicalise {
			t.Errorf("drop reason = %q, want %q", d.Reason, DropCanonicalise)
		}
		if d.Err == nil {
			t.Error("a drop was recorded with no reason attached")
		}
	}
}

// Contexts must stay aligned with the records that survived, or the cache
// projection attaches one record's tags to another's indicator.
func TestBuildContextsStayAlignedWithRecords(t *testing.T) {
	tagged := indicatorRecord(envelope.TypeAuto, "good.example")
	tagged.Context = &envelope.Context{Tags: []string{"marker"}}

	e := env(
		indicatorRecord(envelope.TypeIPv4, "not-an-ip"), // dropped
		tagged,
	)

	got := build(e, "digest")
	if len(got.Batch.Records) != len(got.Contexts) {
		t.Fatalf("%d records but %d contexts", len(got.Batch.Records), len(got.Contexts))
	}
	if len(got.Batch.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(got.Batch.Records))
	}
	if got.Contexts[0] == nil || len(got.Contexts[0].Tags) != 1 || got.Contexts[0].Tags[0] != "marker" {
		t.Errorf("context = %+v, want the surviving record's own tags", got.Contexts[0])
	}
}

// Relationship endpoints go through the same canonicaliser as records, so an
// edge can name an entity by whatever spelling the feed used.
func TestBuildCanonicalisesRelationshipEndpoints(t *testing.T) {
	e := env(indicatorRecord(envelope.TypeAuto, "evil.com"))
	e.Relationships = []envelope.Relationship{{
		Source: envelope.Endpoint{Kind: envelope.KindIndicator, Value: "EVIL[.]com"},
		Target: envelope.Endpoint{Kind: envelope.KindCVE, Value: "cve-2024-3094"},
		Type:   envelope.RelExploits,
	}}

	got := build(e, "digest")
	if len(got.Batch.Relationships) != 1 {
		t.Fatalf("relationships = %d, want 1 (dropped: %v)", len(got.Batch.Relationships), got.Dropped)
	}
	rel := got.Batch.Relationships[0]
	if rel.SourceKey != "evil.com" {
		t.Errorf("source key = %q, want %q", rel.SourceKey, "evil.com")
	}
	if rel.TargetKey != "CVE-2024-3094" {
		t.Errorf("target key = %q, want %q", rel.TargetKey, "CVE-2024-3094")
	}
	// The endpoint resolves to the same key as the record, so they will share
	// one entity row rather than creating a duplicate.
	if rel.SourceKey != got.Batch.Records[0].Entity.CanonicalKey {
		t.Errorf("endpoint key %q does not match record key %q; they would become two entities",
			rel.SourceKey, got.Batch.Records[0].Entity.CanonicalKey)
	}
}

// An endpoint that nothing else in the envelope describes still needs its
// module row, or it gets an entity row and nothing else — invisible to any
// lookup by value, and a violation of the one-to-one module invariant.
func TestBuildGivesEndpointsModuleRows(t *testing.T) {
	e := env(indicatorRecord(envelope.TypeAuto, "evil.com"))
	e.Relationships = []envelope.Relationship{{
		Source: envelope.Endpoint{Kind: envelope.KindIndicator, Value: "exploit-host[.]example"},
		Target: envelope.Endpoint{Kind: envelope.KindCVE, Value: "cve-2021-44228"},
		Type:   envelope.RelExploits,
	}}

	got := build(e, "digest")

	byKey := make(map[string]*store.Record, len(got.Batch.Records))
	for i := range got.Batch.Records {
		byKey[got.Batch.Records[i].Entity.CanonicalKey] = &got.Batch.Records[i]
	}

	host, ok := byKey["exploit-host.example"]
	if !ok {
		t.Fatalf("no record for the indicator endpoint; got %v", slices.Collect(maps.Keys(byKey)))
	}
	if host.Indicator == nil {
		t.Error("the indicator endpoint has no indicator payload")
	} else if host.Indicator.Type != string(envelope.TypeDomain) {
		t.Errorf("endpoint type = %q, want the inferred %q",
			host.Indicator.Type, envelope.TypeDomain)
	}
	// An edge is an assertion, not an observation. Recording a sighting here
	// would invent evidence the source never offered.
	if host.Sighting != nil {
		t.Error("the endpoint was given a sighting; the source never claimed to observe it")
	}

	cve, ok := byKey["CVE-2021-44228"]
	if !ok {
		t.Fatal("no record for the CVE endpoint")
	}
	if cve.CVE == nil || cve.CVE.CVEID != "CVE-2021-44228" {
		t.Errorf("CVE endpoint payload = %+v, want the id filled in", cve.CVE)
	}

	// The described record keeps its sighting and its provenance.
	described, ok := byKey["evil.com"]
	if !ok {
		t.Fatal("the described record went missing")
	}
	if described.Sighting == nil {
		t.Error("the described record lost its sighting")
	}
}

// An endpoint naming an entity the envelope already describes must not produce
// a second, emptier record that overwrites the real one.
func TestBuildDoesNotStubDescribedEntities(t *testing.T) {
	e := env(indicatorRecord(envelope.TypeAuto, "evil[.]com"))
	e.Relationships = []envelope.Relationship{{
		Source: envelope.Endpoint{Kind: envelope.KindIndicator, Value: "EVIL.com"},
		Target: envelope.Endpoint{Kind: envelope.KindCVE, Value: "CVE-2021-44228"},
		Type:   envelope.RelExploits,
	}}

	got := build(e, "digest")

	n := 0
	for i := range got.Batch.Records {
		if got.Batch.Records[i].Entity.CanonicalKey == "evil.com" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d records for evil.com, want 1", n)
	}
	for i := range got.Batch.Records {
		r := &got.Batch.Records[i]
		if r.Entity.CanonicalKey != "evil.com" {
			continue
		}
		if r.Sighting == nil {
			t.Error("the described record was replaced by a stub and lost its sighting")
		}
		if r.Indicator == nil || r.Indicator.RawValue != "evil[.]com" {
			t.Errorf("raw_value = %+v, want the original spelling preserved", r.Indicator)
		}
	}
	if len(got.Batch.Records) != len(got.Contexts) {
		t.Errorf("%d records but %d contexts", len(got.Batch.Records), len(got.Contexts))
	}
}

// A relationship that fails to canonicalise is a relationship drop, not a
// record drop — it must not count towards the "feed format has changed" ratio.
func TestBuildSeparatesRelationshipDrops(t *testing.T) {
	e := env(indicatorRecord(envelope.TypeAuto, "evil.com"))
	e.Relationships = []envelope.Relationship{{
		Source: envelope.Endpoint{Kind: envelope.KindIndicator, Value: "evil.com"},
		Target: envelope.Endpoint{Kind: envelope.KindCVE, Value: "nonsense"},
		Type:   envelope.RelExploits,
	}}

	got := build(e, "digest")
	if len(got.Dropped) != 1 {
		t.Fatalf("dropped = %d, want 1", len(got.Dropped))
	}
	if !got.Dropped[0].IsRelationship {
		t.Error("a relationship failure was not marked as one")
	}
	if got.RecordDrops() != 0 {
		t.Errorf("RecordDrops() = %d, want 0 — a bad edge is not a bad record", got.RecordDrops())
	}
}

// A source cannot have first seen something after it told us about it. Letting
// that through would poison entity.first_seen for every other source.
func TestSeenWindowClampsToObservation(t *testing.T) {
	later := collected.Add(48 * time.Hour)
	earlier := collected.Add(-72 * time.Hour)

	first, last := seenWindow(&envelope.Context{FirstSeen: &later}, collected)
	if !first.Equal(collected) {
		t.Errorf("first_seen = %v, want it clamped to the observation %v", first, collected)
	}

	first, last = seenWindow(&envelope.Context{FirstSeen: &earlier, LastSeen: &later}, collected)
	if !first.Equal(earlier) {
		t.Errorf("first_seen = %v, want the source's earlier claim %v", first, earlier)
	}
	if !last.Equal(later) {
		t.Errorf("last_seen = %v, want the source's later claim %v", last, later)
	}

	first, last = seenWindow(nil, collected)
	if !first.Equal(collected) || !last.Equal(collected) {
		t.Errorf("with no context = (%v, %v), want both %v", first, last, collected)
	}
}

// An empty context must leave the column NULL rather than storing {}.
func TestEncodeContextOmitsEmpty(t *testing.T) {
	if b := encodeContext(nil); b != nil {
		t.Errorf("nil context encoded to %s, want nil", b)
	}
	if b := encodeContext(&envelope.Context{}); b != nil {
		t.Errorf("empty context encoded to %s, want nil", b)
	}

	b := encodeContext(&envelope.Context{TLP: envelope.TLPAmber})
	if b == nil {
		t.Fatal("a context with a TLP encoded to nil")
	}
	var back envelope.Context
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("encoded context is not valid JSON: %v", err)
	}
	if back.TLP != envelope.TLPAmber {
		t.Errorf("round-tripped tlp = %q, want %q", back.TLP, envelope.TLPAmber)
	}
}

func TestBuildBreachDerivesSlug(t *testing.T) {
	date, err := time.Parse("2006-01-02", "2021-06-22")
	if err != nil {
		t.Fatal(err)
	}
	e := env(envelope.Record{
		Kind: envelope.KindBreach,
		Breach: &envelope.Breach{
			Name:       "LinkedIn",
			Domain:     "LinkedIn.COM",
			BreachDate: &envelope.Date{Time: date},
		},
	})

	got := build(e, "digest")
	if len(got.Batch.Records) != 1 {
		t.Fatalf("records = %d, want 1 (dropped: %v)", len(got.Batch.Records), got.Dropped)
	}
	rec := got.Batch.Records[0]
	if rec.Entity.CanonicalKey != "linkedin-2021" {
		t.Errorf("canonical key = %q, want %q", rec.Entity.CanonicalKey, "linkedin-2021")
	}
	// The domain goes through the indicator canonicaliser so it can be joined
	// against domain indicators.
	if rec.Breach.Domain == nil || *rec.Breach.Domain != "linkedin.com" {
		t.Errorf("domain = %v, want %q", rec.Breach.Domain, "linkedin.com")
	}
}

func TestBuildCVENormalisesID(t *testing.T) {
	e := env(envelope.Record{
		Kind: envelope.KindCVE,
		CVE:  &envelope.CVE{CVEID: "cve-2024-3094", Severity: "CRITICAL"},
	})

	got := build(e, "digest")
	if len(got.Batch.Records) != 1 {
		t.Fatalf("records = %d, want 1 (dropped: %v)", len(got.Batch.Records), got.Dropped)
	}
	rec := got.Batch.Records[0]
	if rec.Entity.CanonicalKey != "CVE-2024-3094" || rec.CVE.CVEID != "CVE-2024-3094" {
		t.Errorf("key = %q, cve_id = %q, want both CVE-2024-3094",
			rec.Entity.CanonicalKey, rec.CVE.CVEID)
	}
	if rec.CVE.Severity == nil || *rec.CVE.Severity != "critical" {
		t.Errorf("severity = %v, want lowercased", rec.CVE.Severity)
	}
}

func TestDigestIsStable(t *testing.T) {
	body := []byte(`{"schema_version":"1.0"}`)
	if Digest(body) != Digest(body) {
		t.Fatal("Digest is not deterministic")
	}
	if Digest(body) == Digest([]byte(`{"schema_version":"1.1"}`)) {
		t.Fatal("different messages produced the same digest")
	}
	if len(Digest(body)) != 64 {
		t.Fatalf("digest is %d characters, want 64 hex", len(Digest(body)))
	}
}
