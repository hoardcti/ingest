// Package envelope defines the wire contract between scrapers and the ingest
// service.
//
// The authoritative definition is contract/envelope-v1.schema.json — that is
// what Python and TypeScript collectors generate their types from, and a test
// in this package checks these structs against it so the two cannot drift.
//
// Note the asymmetry between the schema and this decoder. The JSON Schema sets
// additionalProperties:false so that a typo in a hand-written envelope is caught
// at authoring time. The Go decoder deliberately *allows* unknown fields, so a
// collector running a newer minor version of the contract does not break an
// ingest service that has not been redeployed yet. Strict where it helps the
// author, lenient where it keeps production running.
package envelope

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// SchemaMajor is the envelope major version this package implements. Envelopes
// declaring a different major are rejected rather than guessed at.
const SchemaMajor = 1

// SchemaVersion is the version this package writes when producing envelopes.
const SchemaVersion = "1.0"

// Kind names the module that owns a record. It matches entity.kind in the
// database.
type Kind string

// Registered module kinds.
const (
	KindIndicator Kind = "indicator"
	KindCVE       Kind = "cve"
	KindBreach    Kind = "breach"
)

// Kinds lists every kind this build understands, in schema order.
var Kinds = []Kind{KindIndicator, KindCVE, KindBreach}

// ObservableType is the type of an indicator's value.
type ObservableType string

// Observable types. TypeAuto asks the ingest service to infer the type from the
// value, for feeds that ship mixed IOC lists without a type column.
const (
	TypeAuto   ObservableType = "auto"
	TypeIPv4   ObservableType = "ipv4"
	TypeIPv6   ObservableType = "ipv6"
	TypeCIDR   ObservableType = "cidr"
	TypeDomain ObservableType = "domain"
	TypeURL    ObservableType = "url"
	TypeEmail  ObservableType = "email"
	TypeMD5    ObservableType = "md5"
	TypeSHA1   ObservableType = "sha1"
	TypeSHA256 ObservableType = "sha256"
	TypeSHA512 ObservableType = "sha512"
)

// ObservableTypes lists every observable type this build understands.
var ObservableTypes = []ObservableType{
	TypeAuto, TypeIPv4, TypeIPv6, TypeCIDR, TypeDomain, TypeURL, TypeEmail,
	TypeMD5, TypeSHA1, TypeSHA256, TypeSHA512,
}

// RelationshipType is a relationship verb. The vocabulary is deliberately small
// and STIX-flavoured: a curated open list beats an enum you have to migrate
// every time a module needs a new verb.
type RelationshipType string

// Relationship verbs.
const (
	RelIndicates    RelationshipType = "indicates"
	RelExploits     RelationshipType = "exploits"
	RelMitigates    RelationshipType = "mitigates"
	RelAttributedTo RelationshipType = "attributed-to"
	RelTargets      RelationshipType = "targets"
	RelRelatedTo    RelationshipType = "related-to"
	RelDerivedFrom  RelationshipType = "derived-from"
	RelExposedIn    RelationshipType = "exposed-in"
)

// RelationshipTypes lists every relationship verb this build understands.
var RelationshipTypes = []RelationshipType{
	RelIndicates, RelExploits, RelMitigates, RelAttributedTo,
	RelTargets, RelRelatedTo, RelDerivedFrom, RelExposedIn,
}

// TLP is a Traffic Light Protocol 2.0 marking.
type TLP string

// TLP markings.
const (
	TLPClear       TLP = "clear"
	TLPGreen       TLP = "green"
	TLPAmber       TLP = "amber"
	TLPAmberStrict TLP = "amber+strict"
	TLPRed         TLP = "red"
)

// TLPs lists every TLP marking this build understands.
var TLPs = []TLP{TLPClear, TLPGreen, TLPAmber, TLPAmberStrict, TLPRed}

// MaxInlineRaw caps the size of a payload a collector may ship inline for the
// ingest service to archive. Beyond this the collector should archive it and
// send RawRef instead — the queue is not an object store.
const MaxInlineRaw = 1 << 20 // 1 MiB

// Envelope is one delivery from one collector run.
//
// One envelope carrying many records is the intended shape: the ingest service
// writes the whole batch in a single transaction using the COPY protocol, so a
// thousand records cost barely more than one.
type Envelope struct {
	SchemaVersion string    `json:"schema_version"`
	Source        string    `json:"source"`
	SourceRunID   string    `json:"source_run_id,omitempty"`
	CollectedAt   time.Time `json:"collected_at"`

	// ContentHash is the hash of the untouched upstream payload, as
	// "sha256:<hex>". It identifies the payload for archival and provenance.
	//
	// It is deliberately not the idempotency key. Deduplication is on the
	// digest of the delivered message, so that a redelivery is suppressed while
	// an unchanged blocklist collected again tomorrow still records the fact
	// that its entries are still listed.
	ContentHash string `json:"content_hash,omitempty"`

	// RawRef points at the archived upstream payload. Set by the collector if
	// it archived the payload itself; otherwise filled in by the ingest service
	// after it archives Raw.
	RawRef string `json:"raw_ref,omitempty"`

	// Raw is the untouched upstream payload for the ingest service to archive.
	Raw *Raw `json:"raw,omitempty"`

	// DefaultContext applies to every record that does not override it. It
	// saves repeating tlp and tags on ten thousand rows from one feed.
	DefaultContext *Context `json:"default_context,omitempty"`

	Records       []Record       `json:"records"`
	Relationships []Relationship `json:"relationships,omitempty"`
}

// Raw is an inline upstream payload awaiting archival.
type Raw struct {
	MediaType string `json:"media_type,omitempty"`
	Encoding  string `json:"encoding,omitempty"` // "utf8" (default) or "base64"
	Data      string `json:"data"`
}

// Bytes decodes the payload according to Encoding.
func (r *Raw) Bytes() ([]byte, error) {
	switch r.Encoding {
	case "", "utf8":
		return []byte(r.Data), nil
	case "base64":
		b, err := base64.StdEncoding.DecodeString(r.Data)
		if err != nil {
			return nil, fmt.Errorf("decode base64 raw payload: %w", err)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("unknown raw encoding %q", r.Encoding)
	}
}

// ContentType returns the media type, defaulting to application/octet-stream.
func (r *Raw) ContentType() string {
	if r.MediaType == "" {
		return "application/octet-stream"
	}
	return r.MediaType
}

// Context is what a source said about an observation, as opposed to what the
// observation is. It lands on the sighting, not on the entity.
type Context struct {
	FirstSeen  *time.Time     `json:"first_seen,omitempty"`
	LastSeen   *time.Time     `json:"last_seen,omitempty"`
	Confidence *float64       `json:"confidence,omitempty"`
	Tags       []string       `json:"tags,omitempty"`
	TLP        TLP            `json:"tlp,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Record is a single observation. Kind selects which payload field is populated.
type Record struct {
	Kind       Kind       `json:"kind"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
	Context    *Context   `json:"context,omitempty"`

	Indicator *Indicator `json:"indicator,omitempty"`
	CVE       *CVE       `json:"cve,omitempty"`
	Breach    *Breach    `json:"breach,omitempty"`
}

// Indicator is an observable: an IP, domain, URL, email address or file hash.
//
// RawValue, not Value: scrapers report what they saw and do not interpret it. A
// scraper emitting hxxp://evil[.]com is behaving correctly.
type Indicator struct {
	Type     ObservableType `json:"type"`
	RawValue string         `json:"raw_value"`
}

// CVE is a published vulnerability record.
type CVE struct {
	CVEID          string     `json:"cve_id"`
	Summary        string     `json:"summary,omitempty"`
	CVSSScore      *float64   `json:"cvss_score,omitempty"`
	CVSSVector     string     `json:"cvss_vector,omitempty"`
	Severity       string     `json:"severity,omitempty"`
	EPSSScore      *float64   `json:"epss_score,omitempty"`
	KnownExploited *bool      `json:"known_exploited,omitempty"`
	CWE            []string   `json:"cwe,omitempty"`
	PublishedAt    *time.Time `json:"published_at,omitempty"`
	ModifiedAt     *time.Time `json:"modified_at,omitempty"`
	Refs           []any      `json:"refs,omitempty"`
}

// Breach is a disclosed data breach.
type Breach struct {
	Slug        string     `json:"slug,omitempty"`
	Name        string     `json:"name"`
	Domain      string     `json:"domain,omitempty"`
	Description string     `json:"description,omitempty"`
	BreachDate  *Date      `json:"breach_date,omitempty"`
	DisclosedAt *time.Time `json:"disclosed_at,omitempty"`
	RecordCount *int64     `json:"record_count,omitempty"`
	DataClasses []string   `json:"data_classes,omitempty"`
	Verified    *bool      `json:"verified,omitempty"`
}

// Endpoint is one end of a relationship, given as a raw value plus the kind
// that owns it. It is canonicalised exactly as a record would be, so a
// relationship may point at an entity that appears nowhere else in the
// envelope.
type Endpoint struct {
	Kind  Kind           `json:"kind"`
	Type  ObservableType `json:"type,omitempty"` // when Kind is indicator
	Value string         `json:"value"`
}

// Relationship is an edge between two entities.
type Relationship struct {
	Source     Endpoint         `json:"source"`
	Target     Endpoint         `json:"target"`
	Type       RelationshipType `json:"type"`
	Confidence *float64         `json:"confidence,omitempty"`
	FirstSeen  *time.Time       `json:"first_seen,omitempty"`
	LastSeen   *time.Time       `json:"last_seen,omitempty"`
	Metadata   map[string]any   `json:"metadata,omitempty"`
}

// Date is a calendar date with no time or zone, serialised as YYYY-MM-DD.
// Postgres `date` has no notion of a zone and neither should this.
type Date struct {
	time.Time
}

const dateLayout = "2006-01-02"

// MarshalJSON implements [json.Marshaler].
func (d Date) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Format(dateLayout))
}

// UnmarshalJSON implements [json.Unmarshaler].
func (d *Date) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		d.Time = time.Time{}
		return nil
	}
	t, err := time.Parse(dateLayout, s)
	if err != nil {
		return fmt.Errorf("parse date %q: want YYYY-MM-DD: %w", s, err)
	}
	d.Time = t
	return nil
}

// Decode parses an envelope from JSON. Unknown fields are ignored so that a
// collector on a newer minor version of the contract keeps working against an
// older ingest service.
func Decode(b []byte) (*Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}
	return &e, nil
}

// EffectiveObservedAt returns when the source observed this record, falling
// back to the envelope's collection time.
func (r *Record) EffectiveObservedAt(collectedAt time.Time) time.Time {
	if r.ObservedAt != nil && !r.ObservedAt.IsZero() {
		return *r.ObservedAt
	}
	return collectedAt
}

// EffectiveContext merges a record's context over the envelope default. Neither
// input is modified; a nil result means neither side supplied anything.
func (e *Envelope) EffectiveContext(r *Record) *Context {
	if e.DefaultContext == nil {
		return r.Context
	}
	if r.Context == nil {
		return e.DefaultContext
	}

	merged := *e.DefaultContext
	c := r.Context
	if c.FirstSeen != nil {
		merged.FirstSeen = c.FirstSeen
	}
	if c.LastSeen != nil {
		merged.LastSeen = c.LastSeen
	}
	if c.Confidence != nil {
		merged.Confidence = c.Confidence
	}
	if c.TLP != "" {
		merged.TLP = c.TLP
	}
	if len(c.Tags) > 0 {
		// Union rather than override: envelope-level tags describe the feed
		// ("phishing"), record-level tags describe the record ("credential
		// harvesting"). Losing either would be wrong.
		merged.Tags = unionTags(merged.Tags, c.Tags)
	}
	if len(c.Attributes) > 0 {
		attrs := make(map[string]any, len(merged.Attributes)+len(c.Attributes))
		for k, v := range merged.Attributes {
			attrs[k] = v
		}
		for k, v := range c.Attributes {
			attrs[k] = v
		}
		merged.Attributes = attrs
	}
	return &merged
}

func unionTags(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, t := range list {
			if _, ok := seen[t]; ok {
				continue
			}
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}
