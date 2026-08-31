package store

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// A Batch is one envelope after canonicalisation: every value in it is already
// in the exact form the database stores. Nothing in this package normalises
// anything — by the time a batch reaches [Store.WriteBatch] that decision has
// been made once, in internal/canonical.
type Batch struct {
	SourceSlug    string
	SchemaVersion string
	SourceRunID   string

	// EnvelopeDigest is the SHA-256 of the delivered message bytes. It is the
	// idempotency key, and deliberately not ContentHash — see the comment on
	// ingest_envelope in db/migrations/00003_ingest_bookkeeping.sql.
	EnvelopeDigest string

	// ContentHash identifies the upstream payload this envelope was derived
	// from. Provenance, not identity.
	ContentHash string

	RawRef      string
	CollectedAt time.Time

	Records       []Record
	Relationships []Relationship
}

// Record is one entity plus the module payload that describes it, and usually
// the sighting that records who saw it and when.
//
// Sighting is nil for an entity that this envelope names but does not claim to
// have observed — the endpoints of a relationship. "This indicator exploits
// CVE-2021-44228" asserts that the edge exists; it is not a sighting of the CVE,
// and recording one would invent evidence the source never offered.
type Record struct {
	Entity   Entity
	Sighting *Sighting

	// Exactly one of these is set, matching Entity.Kind.
	Indicator *IndicatorFields
	CVE       *CVEFields
	Breach    *BreachFields
}

// Entity is a row in the entity registry.
type Entity struct {
	Kind         string
	CanonicalKey string
	FirstSeen    time.Time
	LastSeen     time.Time
}

// IndicatorFields is the indicator module payload.
type IndicatorFields struct {
	Type     string
	Value    string
	RawValue string
}

// CVEFields is the cve module payload.
type CVEFields struct {
	CVEID          string
	Summary        *string
	CVSSScore      *float64
	CVSSVector     *string
	Severity       *string
	EPSSScore      *float64
	KnownExploited bool
	CWE            []string
	PublishedAt    *time.Time
	ModifiedAt     *time.Time
	Refs           []any
}

// BreachFields is the breach module payload.
type BreachFields struct {
	Slug        string
	Name        string
	Domain      *string
	Description *string
	BreachDate  *time.Time
	DisclosedAt *time.Time
	RecordCount *int64
	DataClasses []string
	Verified    bool
}

// Sighting records that this source reported this entity at this time.
type Sighting struct {
	ObservedAt  time.Time
	ContentHash *string
	RawRef      *string
	Context     []byte // JSON, or nil
}

// Relationship is an edge, with both endpoints given as already-canonicalised
// (kind, key) pairs. Endpoints that are not otherwise in the batch get a bare
// entity row: a feed may legitimately assert "this indicator exploits
// CVE-2024-3094" without also describing the CVE.
type Relationship struct {
	SourceKind, SourceKey string
	TargetKind, TargetKey string

	// Observable types for endpoints of kind "indicator", so the endpoint's
	// module row can be written. Empty for every other kind.
	SourceType, TargetType string

	Type       string
	Confidence *float64
	FirstSeen  time.Time
	LastSeen   time.Time
	Metadata   []byte // JSON, or nil
}

// EntityRef pairs an entity's batch identity with the id the database gave it.
// The ingest service needs these to project indicators into the lookup cache
// without reading them back.
type EntityRef struct {
	Kind         string
	CanonicalKey string
	ID           string
}

// WriteResult reports what one batch actually did.
type WriteResult struct {
	// Duplicate is true when this envelope's digest was already recorded for
	// this source, so nothing was written. Expected under at-least-once
	// delivery, and not an error.
	Duplicate bool

	SourceID pgtype.UUID

	// Entities is every entity the batch touched, including the endpoints of
	// relationships that had no record of their own.
	Entities []EntityRef

	Indicators    int
	CVEs          int
	Breaches      int
	Sightings     int
	Relationships int

	Elapsed time.Duration
}

// entityKey identifies an entity within a batch before it has a database id.
type entityKey struct {
	kind string
	key  string
}
