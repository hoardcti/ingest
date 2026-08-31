package envelope

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Bounds mirrored from contract/envelope-v1.schema.json.
const (
	MaxRecords       = 50000
	MaxRelationships = 50000
	MaxRawValue      = 4096
	MaxTags          = 64
	MaxTagLen        = 128
	MaxSourceLen     = 128
)

// Timestamp sanity bounds. A feed with a broken clock that reports observed_at
// in the year 2263 would otherwise have us provision a sighting partition for
// it, so out-of-range timestamps are rejected at the door rather than absorbed.
var (
	// MinTimestamp predates every CTI feed worth ingesting.
	MinTimestamp = time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	// MaxClockSkew is how far ahead of our clock a source may claim to be.
	MaxClockSkew = 48 * time.Hour
)

var (
	sourceSlugRe  = regexp.MustCompile(`^[a-z0-9]+(?:[-_.][a-z0-9]+)*$`)
	schemaVerRe   = regexp.MustCompile(`^([0-9]+)\.([0-9]+)$`)
	contentHashRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	cveIDRe       = regexp.MustCompile(`^[Cc][Vv][Ee]-[0-9]{4}-[0-9]{4,}$`)
	cweRe         = regexp.MustCompile(`^CWE-[0-9]+$`)
)

// ValidationError is one problem with one field, located by JSON path so that a
// collector author can find it without guessing.
type ValidationError struct {
	Path string
	Msg  string
}

func (e ValidationError) Error() string { return e.Path + ": " + e.Msg }

// ValidationErrors is every problem found in one envelope. Validation does not
// stop at the first failure: a collector author fixing a malformed feed mapping
// wants the whole list, not one error per redeploy.
type ValidationErrors []ValidationError

func (v ValidationErrors) Error() string {
	if len(v) == 0 {
		return "envelope: no errors"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "envelope invalid (%d problem", len(v))
	if len(v) != 1 {
		b.WriteByte('s')
	}
	b.WriteString("): ")
	const show = 10
	for i, e := range v {
		if i == show {
			fmt.Fprintf(&b, "; … and %d more", len(v)-show)
			break
		}
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(e.Error())
	}
	return b.String()
}

type validator struct {
	errs ValidationErrors
	now  time.Time
}

func (v *validator) add(path, format string, args ...any) {
	v.errs = append(v.errs, ValidationError{Path: path, Msg: fmt.Sprintf(format, args...)})
}

// Validate checks an envelope against the contract. A nil return means the
// ingest service can process it; otherwise the result is [ValidationErrors].
//
// This is a hand-written check rather than a JSON Schema evaluation because it
// runs on every envelope on the hot path. TestEnvelopeMatchesJSONSchema keeps
// the two in agreement.
func Validate(e *Envelope) error {
	return validateAt(e, time.Now())
}

func validateAt(e *Envelope, now time.Time) error {
	v := &validator{now: now}

	v.schemaVersion(e.SchemaVersion)
	v.source(e.Source)

	if e.CollectedAt.IsZero() {
		v.add("collected_at", "required")
	} else {
		v.timestamp("collected_at", e.CollectedAt)
	}

	if e.ContentHash != "" && !contentHashRe.MatchString(e.ContentHash) {
		v.add("content_hash", "must be %q, got %q", "sha256:<64 lowercase hex>", e.ContentHash)
	}

	if e.Raw != nil {
		v.raw(e.Raw)
	}
	if e.DefaultContext != nil {
		v.context("default_context", e.DefaultContext)
	}

	switch {
	case len(e.Records) == 0:
		v.add("records", "at least one record required")
	case len(e.Records) > MaxRecords:
		v.add("records", "%d records exceeds the limit of %d; split the envelope",
			len(e.Records), MaxRecords)
	}
	for i := range e.Records {
		v.record(fmt.Sprintf("records[%d]", i), &e.Records[i])
	}

	if len(e.Relationships) > MaxRelationships {
		v.add("relationships", "%d relationships exceeds the limit of %d",
			len(e.Relationships), MaxRelationships)
	}
	for i := range e.Relationships {
		v.relationship(fmt.Sprintf("relationships[%d]", i), &e.Relationships[i])
	}

	if len(v.errs) > 0 {
		return v.errs
	}
	return nil
}

func (v *validator) schemaVersion(s string) {
	if s == "" {
		v.add("schema_version", "required (this build speaks %s)", SchemaVersion)
		return
	}
	m := schemaVerRe.FindStringSubmatch(s)
	if m == nil {
		v.add("schema_version", "must be MAJOR.MINOR, got %q", s)
		return
	}
	major, err := strconv.Atoi(m[1])
	if err != nil || major != SchemaMajor {
		v.add("schema_version",
			"major version %s is not supported; this build speaks %d.x", m[1], SchemaMajor)
	}
}

func (v *validator) source(s string) {
	switch {
	case s == "":
		v.add("source", "required")
	case len(s) > MaxSourceLen:
		v.add("source", "longer than %d characters", MaxSourceLen)
	case !sourceSlugRe.MatchString(s):
		v.add("source", "must be a lowercase slug matching %s, got %q",
			sourceSlugRe.String(), s)
	}
}

func (v *validator) raw(r *Raw) {
	if r.Data == "" {
		v.add("raw.data", "required when raw is present")
		return
	}
	switch r.Encoding {
	case "", "utf8", "base64":
	default:
		v.add("raw.encoding", "must be utf8 or base64, got %q", r.Encoding)
		return
	}
	b, err := r.Bytes()
	if err != nil {
		v.add("raw.data", "%v", err)
		return
	}
	if len(b) > MaxInlineRaw {
		v.add("raw.data",
			"%d bytes exceeds the %d byte inline limit; archive it and send raw_ref instead",
			len(b), MaxInlineRaw)
	}
}

func (v *validator) timestamp(path string, t time.Time) {
	if t.Before(MinTimestamp) {
		v.add(path, "%s predates %s; check the source's date parsing",
			t.Format(time.RFC3339), MinTimestamp.Format("2006"))
		return
	}
	if t.After(v.now.Add(MaxClockSkew)) {
		v.add(path, "%s is more than %s in the future; check the source's clock",
			t.Format(time.RFC3339), MaxClockSkew)
	}
}

func (v *validator) optTimestamp(path string, t *time.Time) {
	if t == nil || t.IsZero() {
		return
	}
	v.timestamp(path, *t)
}

func (v *validator) context(path string, c *Context) {
	v.optTimestamp(path+".first_seen", c.FirstSeen)
	v.optTimestamp(path+".last_seen", c.LastSeen)

	if c.FirstSeen != nil && c.LastSeen != nil &&
		!c.FirstSeen.IsZero() && !c.LastSeen.IsZero() &&
		c.LastSeen.Before(*c.FirstSeen) {
		v.add(path+".last_seen", "is before first_seen")
	}
	if c.Confidence != nil && (*c.Confidence < 0 || *c.Confidence > 1) {
		v.add(path+".confidence", "must be between 0 and 1, got %v", *c.Confidence)
	}
	if c.TLP != "" && !validTLP(c.TLP) {
		v.add(path+".tlp", "unknown marking %q, want one of %s", c.TLP, joinTLPs())
	}
	if len(c.Tags) > MaxTags {
		v.add(path+".tags", "%d tags exceeds the limit of %d", len(c.Tags), MaxTags)
	}
	for i, t := range c.Tags {
		if t == "" {
			v.add(fmt.Sprintf("%s.tags[%d]", path, i), "must not be empty")
		} else if len(t) > MaxTagLen {
			v.add(fmt.Sprintf("%s.tags[%d]", path, i),
				"longer than %d characters", MaxTagLen)
		}
	}
}

func (v *validator) record(path string, r *Record) {
	if r.Context != nil {
		v.context(path+".context", r.Context)
	}
	v.optTimestamp(path+".observed_at", r.ObservedAt)

	// Exactly the payload named by kind, and no other.
	present := map[Kind]bool{
		KindIndicator: r.Indicator != nil,
		KindCVE:       r.CVE != nil,
		KindBreach:    r.Breach != nil,
	}

	switch r.Kind {
	case "":
		v.add(path+".kind", "required")
	case KindIndicator, KindCVE, KindBreach:
		if !present[r.Kind] {
			v.add(path+"."+string(r.Kind), "required when kind is %q", r.Kind)
		}
	default:
		v.add(path+".kind", "unknown kind %q, want one of %s", r.Kind, joinKinds())
	}

	for k, ok := range present {
		if ok && k != r.Kind {
			v.add(path+"."+string(k), "present but kind is %q", r.Kind)
		}
	}

	if r.Indicator != nil {
		v.indicator(path+".indicator", r.Indicator)
	}
	if r.CVE != nil {
		v.cve(path+".cve", r.CVE)
	}
	if r.Breach != nil {
		v.breach(path+".breach", r.Breach)
	}
}

func (v *validator) indicator(path string, i *Indicator) {
	if i.Type == "" {
		v.add(path+".type", "required (use %q to have the value inferred)", TypeAuto)
	} else if !validObservableType(i.Type) {
		v.add(path+".type", "unknown type %q, want one of %s", i.Type, joinObservableTypes())
	}
	switch {
	case i.RawValue == "":
		v.add(path+".raw_value", "required")
	case len(i.RawValue) > MaxRawValue:
		v.add(path+".raw_value", "longer than %d characters", MaxRawValue)
	}
}

func (v *validator) cve(path string, c *CVE) {
	switch {
	case c.CVEID == "":
		v.add(path+".cve_id", "required")
	case !cveIDRe.MatchString(c.CVEID):
		v.add(path+".cve_id", "must look like CVE-YYYY-NNNN, got %q", c.CVEID)
	}
	if c.CVSSScore != nil && (*c.CVSSScore < 0 || *c.CVSSScore > 10) {
		v.add(path+".cvss_score", "must be between 0 and 10, got %v", *c.CVSSScore)
	}
	if c.EPSSScore != nil && (*c.EPSSScore < 0 || *c.EPSSScore > 1) {
		v.add(path+".epss_score", "must be between 0 and 1, got %v", *c.EPSSScore)
	}
	if c.Severity != "" {
		switch strings.ToLower(c.Severity) {
		case "none", "low", "medium", "high", "critical":
		default:
			v.add(path+".severity",
				"unknown severity %q, want none/low/medium/high/critical", c.Severity)
		}
	}
	for i, w := range c.CWE {
		if !cweRe.MatchString(w) {
			v.add(fmt.Sprintf("%s.cwe[%d]", path, i), "must look like CWE-79, got %q", w)
		}
	}
	v.optTimestamp(path+".published_at", c.PublishedAt)
	v.optTimestamp(path+".modified_at", c.ModifiedAt)
}

func (v *validator) breach(path string, b *Breach) {
	if strings.TrimSpace(b.Name) == "" {
		v.add(path+".name", "required")
	}
	if b.RecordCount != nil && *b.RecordCount < 0 {
		v.add(path+".record_count", "must not be negative, got %d", *b.RecordCount)
	}
	v.optTimestamp(path+".disclosed_at", b.DisclosedAt)
	if b.BreachDate != nil && !b.BreachDate.IsZero() {
		v.timestamp(path+".breach_date", b.BreachDate.Time)
	}
}

func (v *validator) relationship(path string, r *Relationship) {
	v.endpoint(path+".source", &r.Source)
	v.endpoint(path+".target", &r.Target)

	if r.Type == "" {
		v.add(path+".type", "required")
	} else if !validRelationshipType(r.Type) {
		v.add(path+".type", "unknown verb %q, want one of %s", r.Type, joinRelationshipTypes())
	}
	if r.Confidence != nil && (*r.Confidence < 0 || *r.Confidence > 1) {
		v.add(path+".confidence", "must be between 0 and 1, got %v", *r.Confidence)
	}
	v.optTimestamp(path+".first_seen", r.FirstSeen)
	v.optTimestamp(path+".last_seen", r.LastSeen)
}

func (v *validator) endpoint(path string, e *Endpoint) {
	switch e.Kind {
	case "":
		v.add(path+".kind", "required")
	case KindIndicator, KindCVE, KindBreach:
	default:
		v.add(path+".kind", "unknown kind %q, want one of %s", e.Kind, joinKinds())
	}
	if e.Type != "" {
		if e.Kind != KindIndicator {
			v.add(path+".type", "only meaningful when kind is %q", KindIndicator)
		} else if !validObservableType(e.Type) {
			v.add(path+".type", "unknown type %q, want one of %s", e.Type, joinObservableTypes())
		}
	}
	switch {
	case e.Value == "":
		v.add(path+".value", "required")
	case len(e.Value) > MaxRawValue:
		v.add(path+".value", "longer than %d characters", MaxRawValue)
	}
}

func validTLP(t TLP) bool {
	for _, k := range TLPs {
		if k == t {
			return true
		}
	}
	return false
}

func validObservableType(t ObservableType) bool {
	for _, k := range ObservableTypes {
		if k == t {
			return true
		}
	}
	return false
}

func validRelationshipType(t RelationshipType) bool {
	for _, k := range RelationshipTypes {
		if k == t {
			return true
		}
	}
	return false
}

func joinKinds() string {
	s := make([]string, len(Kinds))
	for i, k := range Kinds {
		s[i] = string(k)
	}
	return strings.Join(s, ", ")
}

func joinTLPs() string {
	s := make([]string, len(TLPs))
	for i, k := range TLPs {
		s[i] = string(k)
	}
	return strings.Join(s, ", ")
}

func joinObservableTypes() string {
	s := make([]string, len(ObservableTypes))
	for i, k := range ObservableTypes {
		s[i] = string(k)
	}
	return strings.Join(s, ", ")
}

func joinRelationshipTypes() string {
	s := make([]string, len(RelationshipTypes))
	for i, k := range RelationshipTypes {
		s[i] = string(k)
	}
	return strings.Join(s, ", ")
}
