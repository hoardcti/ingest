package store_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hoardcti/ingest/internal/store"
)

// TestDatabaseEnv names the connection string these tests run against. They are
// skipped without it, because the write path is almost entirely SQL and a mock
// would only assert that the mock matches itself.
//
//	docker compose up -d postgres
//	HOARDCTI_TEST_DATABASE_URL=postgres://hoardcti:hoardcti@localhost:5432/hoardcti_test \
//	    go test ./internal/store/
const TestDatabaseEnv = "HOARDCTI_TEST_DATABASE_URL"

func newTestStore(t *testing.T) *store.Store {
	t.Helper()

	dsn := os.Getenv(TestDatabaseEnv)
	if dsn == "" {
		t.Skipf("set %s to run the store integration tests", TestDatabaseEnv)
	}

	ctx := context.Background()
	st, err := store.Open(ctx, store.Options{
		DSN:                 dsn,
		MaxConns:            8,
		AutoRegisterSources: true,
		Logger:              slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
	})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)

	m, err := store.NewMigrator(st, slog.Default())
	if err != nil {
		t.Fatalf("new migrator: %v", err)
	}
	defer m.Close()
	if _, err := m.Up(ctx); err != nil {
		t.Fatalf("migrate up: %v", err)
	}

	// A clean slate per test. sighting is partitioned; truncating the parent
	// takes the partitions with it.
	if _, err := st.Pool().Exec(ctx, `
		TRUNCATE ingest_dead_letter, ingest_envelope, sighting, relationship,
		         indicator, cve, breach, entity, source
		RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return st
}

var observed = time.Date(2026, 8, 31, 6, 0, 0, 0, time.UTC)

func batch(digest string, records ...store.Record) *store.Batch {
	return &store.Batch{
		SourceSlug:     "test-feed",
		SchemaVersion:  "1.0",
		EnvelopeDigest: digest,
		ContentHash:    "sha256:" + digest,
		CollectedAt:    observed,
		Records:        records,
	}
}

func indicator(value string) store.Record {
	return store.Record{
		Entity: store.Entity{
			Kind: "indicator", CanonicalKey: value,
			FirstSeen: observed, LastSeen: observed,
		},
		Indicator: &store.IndicatorFields{Type: "domain", Value: value, RawValue: value},
		Sighting:  &store.Sighting{ObservedAt: observed},
	}
}

// closeEnough compares a value read back from a `real` column. Postgres `real`
// is float4, so a float64 written as 0.74 comes back as 0.74000000953674316 —
// the value is intact at the precision the column stores, but exact float64
// equality was never going to hold. CVSS (one decimal) and EPSS (five) both sit
// well inside float4's range, so `real` is the right column type; this is what
// checking it looks like.
func closeEnough(got *float64, want float64) bool {
	if got == nil {
		return false
	}
	return float32(*got) == float32(want)
}

func deref(f *float64) any {
	if f == nil {
		return "<nil>"
	}
	return *f
}

func count(t *testing.T, st *store.Store, table string) int {
	t.Helper()
	var n int
	if err := st.Pool().QueryRow(context.Background(),
		"SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestWriteBatch(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	res, err := st.WriteBatch(ctx, batch("d1", indicator("evil.com"), indicator("worse.com")))
	if err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	if res.Duplicate {
		t.Fatal("a first write reported itself as a duplicate")
	}
	if len(res.Entities) != 2 {
		t.Errorf("entities = %d, want 2", len(res.Entities))
	}
	if res.Sightings != 2 {
		t.Errorf("sightings = %d, want 2", res.Sightings)
	}
	if got := count(t, st, "entity"); got != 2 {
		t.Errorf("entity rows = %d, want 2", got)
	}
	if got := count(t, st, "indicator"); got != 2 {
		t.Errorf("indicator rows = %d, want 2", got)
	}
	if got := count(t, st, "sighting"); got != 2 {
		t.Errorf("sighting rows = %d, want 2", got)
	}
}

// At-least-once delivery guarantees this happens. The second attempt must write
// nothing at all — not even a sighting.
func TestWriteBatchIsIdempotentPerDigest(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if _, err := st.WriteBatch(ctx, batch("same", indicator("evil.com"))); err != nil {
		t.Fatalf("first write: %v", err)
	}
	res, err := st.WriteBatch(ctx, batch("same", indicator("evil.com")))
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	if !res.Duplicate {
		t.Fatal("redelivering the same envelope was not recognised as a duplicate")
	}
	if got := count(t, st, "sighting"); got != 1 {
		t.Errorf("sighting rows = %d, want 1 — a redelivery created a second observation", got)
	}
}

// A blocklist re-collected the next day and found unchanged has the same
// content hash but a new digest, and must record that its entries are still
// listed. This is the case that keying idempotency on content_hash would break.
func TestReCollectionRecordsNewSightings(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	first := batch("run-1", indicator("evil.com"))
	first.ContentHash = "sha256:unchanged"
	if _, err := st.WriteBatch(ctx, first); err != nil {
		t.Fatalf("first collection: %v", err)
	}

	second := batch("run-2", indicator("evil.com"))
	second.ContentHash = "sha256:unchanged" // identical upstream payload
	second.Records[0].Sighting.ObservedAt = observed.Add(24 * time.Hour)
	second.Records[0].Entity.LastSeen = observed.Add(24 * time.Hour)

	res, err := st.WriteBatch(ctx, second)
	if err != nil {
		t.Fatalf("second collection: %v", err)
	}
	if res.Duplicate {
		t.Fatal("a fresh collection of unchanged content was suppressed as a duplicate")
	}
	if got := count(t, st, "sighting"); got != 2 {
		t.Errorf("sighting rows = %d, want 2", got)
	}
	// Still one entity: the indicator did not become two.
	if got := count(t, st, "entity"); got != 1 {
		t.Errorf("entity rows = %d, want 1", got)
	}
}

// UNIQUE (kind, canonical_key) is the deduplication guarantee for the whole
// system. This is the test that it actually holds through the write path.
func TestEntityDeduplicates(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	// The same indicator twice within one envelope, which ON CONFLICT alone
	// would refuse to handle.
	if _, err := st.WriteBatch(ctx, batch("d1", indicator("evil.com"), indicator("evil.com"))); err != nil {
		t.Fatalf("write with an intra-batch duplicate: %v", err)
	}
	if got := count(t, st, "entity"); got != 1 {
		t.Fatalf("entity rows = %d, want 1", got)
	}
	if got := count(t, st, "sighting"); got != 2 {
		t.Errorf("sighting rows = %d, want 2 — both observations should be kept", got)
	}

	// And again across envelopes.
	if _, err := st.WriteBatch(ctx, batch("d2", indicator("evil.com"))); err != nil {
		t.Fatalf("second envelope: %v", err)
	}
	if got := count(t, st, "entity"); got != 1 {
		t.Errorf("entity rows = %d, want 1", got)
	}
}

// first_seen only ever moves backwards and last_seen only forwards, whatever
// order envelopes arrive in.
func TestSeenWindowWidens(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	mid := indicator("evil.com")
	if _, err := st.WriteBatch(ctx, batch("d1", mid)); err != nil {
		t.Fatalf("write: %v", err)
	}

	early := indicator("evil.com")
	early.Entity.FirstSeen = observed.Add(-48 * time.Hour)
	early.Entity.LastSeen = observed.Add(-48 * time.Hour)
	early.Sighting.ObservedAt = observed.Add(-48 * time.Hour)
	if _, err := st.WriteBatch(ctx, batch("d2", early)); err != nil {
		t.Fatalf("backdated write: %v", err)
	}

	late := indicator("evil.com")
	late.Entity.FirstSeen = observed.Add(48 * time.Hour)
	late.Entity.LastSeen = observed.Add(48 * time.Hour)
	late.Sighting.ObservedAt = observed.Add(48 * time.Hour)
	if _, err := st.WriteBatch(ctx, batch("d3", late)); err != nil {
		t.Fatalf("forward-dated write: %v", err)
	}

	var first, last time.Time
	if err := st.Pool().QueryRow(ctx,
		`SELECT first_seen, last_seen FROM entity WHERE canonical_key = 'evil.com'`,
	).Scan(&first, &last); err != nil {
		t.Fatalf("read entity: %v", err)
	}
	if !first.Equal(observed.Add(-48 * time.Hour)) {
		t.Errorf("first_seen = %v, want the earliest claim", first)
	}
	if !last.Equal(observed.Add(48 * time.Hour)) {
		t.Errorf("last_seen = %v, want the latest claim", last)
	}
}

// An enrichment feed that only knows the EPSS score must not blank out the
// summary another feed supplied, and must not be able to clear known_exploited.
func TestCVEMergePreservesFields(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	summary := "Malicious code in the upstream tarballs of xz."
	score := 10.0
	full := store.Record{
		Entity: store.Entity{Kind: "cve", CanonicalKey: "CVE-2024-3094",
			FirstSeen: observed, LastSeen: observed},
		CVE: &store.CVEFields{
			CVEID: "CVE-2024-3094", Summary: &summary, CVSSScore: &score,
			KnownExploited: true, CWE: []string{"CWE-506"},
		},
		Sighting: &store.Sighting{ObservedAt: observed},
	}
	if _, err := st.WriteBatch(ctx, batch("d1", full)); err != nil {
		t.Fatalf("first write: %v", err)
	}

	epss := 0.74
	sparse := store.Record{
		Entity: store.Entity{Kind: "cve", CanonicalKey: "CVE-2024-3094",
			FirstSeen: observed, LastSeen: observed},
		CVE: &store.CVEFields{
			CVEID: "CVE-2024-3094", EPSSScore: &epss, KnownExploited: false,
		},
		Sighting: &store.Sighting{ObservedAt: observed},
	}
	if _, err := st.WriteBatch(ctx, batch("d2", sparse)); err != nil {
		t.Fatalf("enrichment write: %v", err)
	}

	var (
		gotSummary *string
		gotScore   *float64
		gotEPSS    *float64
		gotExploit bool
		gotCWE     []string
	)
	if err := st.Pool().QueryRow(ctx, `
		SELECT summary, cvss_score, epss_score, known_exploited, cwe
		FROM cve WHERE cve_id = 'CVE-2024-3094'`,
	).Scan(&gotSummary, &gotScore, &gotEPSS, &gotExploit, &gotCWE); err != nil {
		t.Fatalf("read cve: %v", err)
	}

	if gotSummary == nil || *gotSummary != summary {
		t.Errorf("summary = %v, want it preserved by the sparse update", gotSummary)
	}
	if !closeEnough(gotScore, score) {
		t.Errorf("cvss_score = %v, want it preserved (%v)", deref(gotScore), score)
	}
	if !closeEnough(gotEPSS, epss) {
		t.Errorf("epss_score = %v, want the enrichment's %v", deref(gotEPSS), epss)
	}
	if !gotExploit {
		t.Error("known_exploited was cleared by a feed that simply did not mention it")
	}
	if len(gotCWE) != 1 || gotCWE[0] != "CWE-506" {
		t.Errorf("cwe = %v, want it preserved", gotCWE)
	}
}

func TestRelationshipUpsert(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	conf := 0.7
	b := batch("d1", indicator("evil.com"))
	b.Relationships = []store.Relationship{{
		SourceKind: "indicator", SourceKey: "evil.com",
		TargetKind: "cve", TargetKey: "CVE-2024-3094",
		Type: "exploits", Confidence: &conf,
		FirstSeen: observed, LastSeen: observed,
	}}

	res, err := st.WriteBatch(ctx, b)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if res.Relationships != 1 {
		t.Errorf("relationships = %d, want 1", res.Relationships)
	}
	// The CVE endpoint had no record of its own, so it must have been created
	// as a bare entity.
	if got := count(t, st, "entity"); got != 2 {
		t.Errorf("entity rows = %d, want 2 (the indicator and the endpoint)", got)
	}
	if got := count(t, st, "cve"); got != 0 {
		t.Errorf("cve rows = %d, want 0 — an endpoint is not a described record", got)
	}

	// The same edge again, with a wider window, must merge rather than duplicate.
	b2 := batch("d2", indicator("evil.com"))
	b2.Relationships = []store.Relationship{{
		SourceKind: "indicator", SourceKey: "evil.com",
		TargetKind: "cve", TargetKey: "CVE-2024-3094",
		Type:      "exploits",
		FirstSeen: observed.Add(-24 * time.Hour),
		LastSeen:  observed.Add(24 * time.Hour),
	}}
	if _, err := st.WriteBatch(ctx, b2); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if got := count(t, st, "relationship"); got != 1 {
		t.Fatalf("relationship rows = %d, want 1", got)
	}

	var (
		gotFirst, gotLast time.Time
		gotConf           *float64
	)
	if err := st.Pool().QueryRow(ctx,
		`SELECT first_seen, last_seen, confidence FROM relationship`,
	).Scan(&gotFirst, &gotLast, &gotConf); err != nil {
		t.Fatalf("read relationship: %v", err)
	}
	if !gotFirst.Equal(observed.Add(-24 * time.Hour)) {
		t.Errorf("first_seen = %v, want the earlier claim", gotFirst)
	}
	if !gotLast.Equal(observed.Add(24 * time.Hour)) {
		t.Errorf("last_seen = %v, want the later claim", gotLast)
	}
	if !closeEnough(gotConf, conf) {
		t.Errorf("confidence = %v, want %v preserved by the update that omitted it",
			deref(gotConf), conf)
	}
}

// A self-edge asserts nothing and would live forever.
func TestRelationshipSelfEdgeDropped(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	b := batch("d1", indicator("evil.com"))
	b.Relationships = []store.Relationship{{
		SourceKind: "indicator", SourceKey: "evil.com",
		TargetKind: "indicator", TargetKey: "evil.com",
		Type: "related-to", FirstSeen: observed, LastSeen: observed,
	}}
	if _, err := st.WriteBatch(ctx, b); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := count(t, st, "relationship"); got != 0 {
		t.Errorf("relationship rows = %d, want 0", got)
	}
}

// Sightings must land in a real monthly partition, never in sighting_default —
// rows there block the creation of the partition that should have held them.
func TestSightingPartitioning(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	future := observed.AddDate(0, 3, 0)
	rec := indicator("evil.com")
	rec.Sighting.ObservedAt = future
	rec.Entity.LastSeen = future

	if _, err := st.WriteBatch(ctx, batch("d1", rec)); err != nil {
		t.Fatalf("write into a future month: %v", err)
	}

	n, err := st.DefaultPartitionRows(ctx)
	if err != nil {
		t.Fatalf("count default partition: %v", err)
	}
	if n != 0 {
		t.Errorf("%d rows landed in sighting_default; the partition was not provisioned", n)
	}

	var partition string
	if err := st.Pool().QueryRow(ctx,
		`SELECT tableoid::regclass::text FROM sighting LIMIT 1`).Scan(&partition); err != nil {
		t.Fatalf("read partition: %v", err)
	}
	want := "sighting_" + future.UTC().Format("2006_01")
	if partition != want {
		t.Errorf("sighting landed in %s, want %s", partition, want)
	}
}

func TestRetentionDropsPartitions(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	old := observed.AddDate(-2, 0, 0)
	rec := indicator("evil.com")
	rec.Sighting.ObservedAt = old
	rec.Entity.FirstSeen = old
	rec.Entity.LastSeen = old
	if _, err := st.WriteBatch(ctx, batch("d1", rec)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := count(t, st, "sighting"); got != 1 {
		t.Fatalf("sighting rows = %d, want 1", got)
	}

	dropped, err := st.DropSightingPartitionsBefore(ctx, observed.AddDate(-1, 0, 0))
	if err != nil {
		t.Fatalf("drop partitions: %v", err)
	}
	if len(dropped) == 0 {
		t.Fatal("no partitions were dropped")
	}
	if got := count(t, st, "sighting"); got != 0 {
		t.Errorf("sighting rows = %d after retention, want 0", got)
	}
	// The entity itself survives: retention drops observations, not knowledge.
	if got := count(t, st, "entity"); got != 1 {
		t.Errorf("entity rows = %d, want 1 — retention must not delete entities", got)
	}
}

func TestUnknownSourceRejected(t *testing.T) {
	dsn := os.Getenv(TestDatabaseEnv)
	if dsn == "" {
		t.Skipf("set %s to run the store integration tests", TestDatabaseEnv)
	}

	// A separate store with auto-registration off, which is the production
	// setting: an unknown slug is nearly always a typo in a collector's config.
	st := newTestStore(t)
	strict, err := store.Open(context.Background(), store.Options{
		DSN: dsn, MaxConns: 2, AutoRegisterSources: false,
	})
	if err != nil {
		t.Fatalf("open strict store: %v", err)
	}
	defer strict.Close()
	_ = st

	_, err = strict.WriteBatch(context.Background(),
		batch("d1", indicator("evil.com")))
	if !errors.Is(err, store.ErrUnknownSource) {
		t.Errorf("error = %v, want ErrUnknownSource", err)
	}
}

func TestDisabledSourceRejected(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if _, err := st.UpsertSource(ctx, "test-feed", "Test", "", "clear", false); err != nil {
		t.Fatalf("upsert source: %v", err)
	}
	_, err := st.WriteBatch(ctx, batch("d1", indicator("evil.com")))
	if !errors.Is(err, store.ErrSourceDisabled) {
		t.Errorf("error = %v, want ErrSourceDisabled", err)
	}
}

func TestDeadLetter(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	// Deliberately not valid JSON: the reason a payload is dead-lettered may be
	// that it could not be parsed, and the evidence still has to survive.
	if err := st.DeadLetter(ctx, "test-feed", "1-0", "decode", "unexpected end of input",
		[]byte("{not json")); err != nil {
		t.Fatalf("DeadLetter: %v", err)
	}
	if got := count(t, st, "ingest_dead_letter"); got != 1 {
		t.Errorf("dead letter rows = %d, want 1", got)
	}

	if err := st.DeadLetter(ctx, "test-feed", "1-1", "validate", "bad source",
		[]byte(`{"source":"x"}`)); err != nil {
		t.Fatalf("DeadLetter with valid JSON: %v", err)
	}
	if got := count(t, st, "ingest_dead_letter"); got != 2 {
		t.Errorf("dead letter rows = %d, want 2", got)
	}
}

func TestMigrationsRoundTrip(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	m, err := store.NewMigrator(st, slog.Default())
	if err != nil {
		t.Fatalf("new migrator: %v", err)
	}
	defer m.Close()

	// Every migration must be reversible, or a bad deploy has no way back.
	if _, err := m.DownTo(ctx, 0); err != nil {
		t.Fatalf("roll everything back: %v", err)
	}
	v, err := m.Version(ctx)
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if v != 0 {
		t.Errorf("schema version after full rollback = %d, want 0", v)
	}

	if _, err := m.Up(ctx); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	pending, err := m.HasPending(ctx)
	if err != nil {
		t.Fatalf("has pending: %v", err)
	}
	if pending {
		t.Error("migrations still pending after Up")
	}
}

func TestSourceLifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	src, err := st.UpsertSource(ctx, "abuse-ch-urlhaus", "URLhaus", "https://urlhaus.abuse.ch/", "clear", true)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if src.ID == (pgtype.UUID{}) {
		t.Error("upsert returned a zero id")
	}

	// An update must not create a second row, and must be visible immediately
	// despite the resolve cache.
	if _, err := st.UpsertSource(ctx, "abuse-ch-urlhaus", "URLhaus (renamed)", "", "amber", true); err != nil {
		t.Fatalf("update: %v", err)
	}
	sources, err := st.ListSources(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(sources) != 1 {
		t.Fatalf("sources = %d, want 1", len(sources))
	}
	if sources[0].Name != "URLhaus (renamed)" {
		t.Errorf("name = %q, want the updated one", sources[0].Name)
	}

	resolved, err := st.ResolveSource(ctx, "abuse-ch-urlhaus")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.ID != src.ID {
		t.Error("resolve returned a different id from upsert")
	}
}
