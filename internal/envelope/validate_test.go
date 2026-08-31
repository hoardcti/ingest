package envelope

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func minimal() *Envelope {
	return &Envelope{
		SchemaVersion: SchemaVersion,
		Source:        "abuse-ch-urlhaus",
		CollectedAt:   time.Date(2026, 8, 31, 6, 0, 0, 0, time.UTC),
		Records: []Record{{
			Kind:      KindIndicator,
			Indicator: &Indicator{Type: TypeDomain, RawValue: "evil.com"},
		}},
	}
}

func TestValidateAcceptsMinimal(t *testing.T) {
	if err := Validate(minimal()); err != nil {
		t.Fatalf("minimal envelope rejected: %v", err)
	}
}

// Every case names the field it should complain about, so a validator that
// fails for the wrong reason is caught too.
func TestValidateRejects(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*Envelope)
		wantPath string
	}{
		{"missing schema version", func(e *Envelope) { e.SchemaVersion = "" }, "schema_version"},
		{"future major version", func(e *Envelope) { e.SchemaVersion = "2.0" }, "schema_version"},
		{"malformed version", func(e *Envelope) { e.SchemaVersion = "one" }, "schema_version"},
		{"missing source", func(e *Envelope) { e.Source = "" }, "source"},
		{"uppercase source", func(e *Envelope) { e.Source = "Abuse-CH" }, "source"},
		{"source with space", func(e *Envelope) { e.Source = "abuse ch" }, "source"},
		{"missing collected_at", func(e *Envelope) { e.CollectedAt = time.Time{} }, "collected_at"},
		{"no records", func(e *Envelope) { e.Records = nil }, "records"},
		{"bad content hash", func(e *Envelope) { e.ContentHash = "md5:abc" }, "content_hash"},
		{"missing kind", func(e *Envelope) { e.Records[0].Kind = "" }, "records[0].kind"},
		{"unknown kind", func(e *Envelope) { e.Records[0].Kind = "actor" }, "records[0].kind"},
		{"payload missing for kind", func(e *Envelope) { e.Records[0].Indicator = nil }, "records[0].indicator"},
		{"wrong payload for kind", func(e *Envelope) {
			e.Records[0].CVE = &CVE{CVEID: "CVE-2024-3094"}
		}, "records[0].cve"},
		{"indicator with no value", func(e *Envelope) { e.Records[0].Indicator.RawValue = "" },
			"records[0].indicator.raw_value"},
		{"unknown observable type", func(e *Envelope) { e.Records[0].Indicator.Type = "registry_key" },
			"records[0].indicator.type"},
		{"confidence above one", func(e *Envelope) {
			c := 1.5
			e.Records[0].Context = &Context{Confidence: &c}
		}, "records[0].context.confidence"},
		{"unknown tlp", func(e *Envelope) {
			e.Records[0].Context = &Context{TLP: "orange"}
		}, "records[0].context.tlp"},
		{"last_seen before first_seen", func(e *Envelope) {
			first := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
			last := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
			e.Records[0].Context = &Context{FirstSeen: &first, LastSeen: &last}
		}, "records[0].context.last_seen"},
		{"unknown relationship verb", func(e *Envelope) {
			e.Relationships = []Relationship{{
				Source: Endpoint{Kind: KindIndicator, Value: "a.com"},
				Target: Endpoint{Kind: KindIndicator, Value: "b.com"},
				Type:   "supersedes",
			}}
		}, "relationships[0].type"},
		{"endpoint type on non-indicator", func(e *Envelope) {
			e.Relationships = []Relationship{{
				Source: Endpoint{Kind: KindCVE, Type: TypeDomain, Value: "CVE-2024-3094"},
				Target: Endpoint{Kind: KindIndicator, Value: "b.com"},
				Type:   RelExploits,
			}}
		}, "relationships[0].source.type"},
		{"bad cve id", func(e *Envelope) {
			e.Records[0] = Record{Kind: KindCVE, CVE: &CVE{CVEID: "CVE-24-1"}}
		}, "records[0].cve.cve_id"},
		{"cvss out of range", func(e *Envelope) {
			s := 11.0
			e.Records[0] = Record{Kind: KindCVE, CVE: &CVE{CVEID: "CVE-2024-3094", CVSSScore: &s}}
		}, "records[0].cve.cvss_score"},
		{"malformed cwe", func(e *Envelope) {
			e.Records[0] = Record{Kind: KindCVE, CVE: &CVE{CVEID: "CVE-2024-3094", CWE: []string{"79"}}}
		}, "records[0].cve.cwe[0]"},
		{"breach with no name", func(e *Envelope) {
			e.Records[0] = Record{Kind: KindBreach, Breach: &Breach{Name: "  "}}
		}, "records[0].breach.name"},
		{"bad raw encoding", func(e *Envelope) {
			e.Raw = &Raw{Encoding: "rot13", Data: "abc"}
		}, "raw.encoding"},
		{"undecodable base64", func(e *Envelope) {
			e.Raw = &Raw{Encoding: "base64", Data: "not!base64!"}
		}, "raw.data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := minimal()
			tt.mutate(e)

			err := Validate(e)
			if err == nil {
				t.Fatalf("envelope accepted, want a complaint about %s", tt.wantPath)
			}
			var ve ValidationErrors
			if !errors.As(err, &ve) {
				t.Fatalf("error is %T, want ValidationErrors", err)
			}
			for _, p := range ve {
				if p.Path == tt.wantPath {
					return
				}
			}
			t.Errorf("no complaint about %s; got: %v", tt.wantPath, err)
		})
	}
}

// A feed with a broken clock must not be able to make us provision a sighting
// partition for the year 2263.
func TestValidateRejectsAbsurdTimestamps(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)

	far := now.AddDate(200, 0, 0)
	e := minimal()
	e.CollectedAt = far
	if err := validateAt(e, now); err == nil {
		t.Error("a collected_at two centuries in the future was accepted")
	}

	old := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	e = minimal()
	e.Records[0].ObservedAt = &old
	if err := validateAt(e, now); err == nil {
		t.Error("an observed_at in 1970 was accepted")
	}

	// Modest skew is normal and must not be rejected.
	near := now.Add(time.Hour)
	e = minimal()
	e.CollectedAt = near
	if err := validateAt(e, now); err != nil {
		t.Errorf("an hour of clock skew was rejected: %v", err)
	}
}

// Validation reports everything at once: a collector author fixing a feed
// mapping wants the whole list, not one error per redeploy.
func TestValidateReportsEveryProblem(t *testing.T) {
	e := minimal()
	e.SchemaVersion = ""
	e.Source = "NOT A SLUG"
	e.Records[0].Indicator.RawValue = ""

	err := Validate(e)
	var ve ValidationErrors
	if !errors.As(err, &ve) {
		t.Fatalf("error is %T, want ValidationErrors", err)
	}
	if len(ve) < 3 {
		t.Errorf("reported %d problems, want at least 3: %v", len(ve), ve)
	}
	if !strings.Contains(err.Error(), "3 problems") &&
		!strings.Contains(err.Error(), "problems") {
		t.Errorf("error summary does not say how many problems there are: %q", err.Error())
	}
}

func TestEffectiveContext(t *testing.T) {
	conf := 0.9
	e := &Envelope{
		DefaultContext: &Context{
			TLP:        TLPAmber,
			Tags:       []string{"phishing"},
			Attributes: map[string]any{"feed": "x"},
		},
	}
	r := &Record{
		Context: &Context{
			Confidence: &conf,
			Tags:       []string{"credential-harvesting"},
			Attributes: map[string]any{"row": 12},
		},
	}

	got := e.EffectiveContext(r)

	if got.TLP != TLPAmber {
		t.Errorf("tlp = %q, want inherited %q", got.TLP, TLPAmber)
	}
	if got.Confidence == nil || *got.Confidence != conf {
		t.Errorf("confidence = %v, want the record's %v", got.Confidence, conf)
	}
	// Tags union rather than override: envelope tags describe the feed, record
	// tags describe the record, and losing either would be wrong.
	if len(got.Tags) != 2 {
		t.Errorf("tags = %v, want both the envelope's and the record's", got.Tags)
	}
	if got.Attributes["feed"] != "x" || got.Attributes["row"] != 12 {
		t.Errorf("attributes = %v, want both merged", got.Attributes)
	}

	// The default must not have been mutated by the merge.
	if len(e.DefaultContext.Tags) != 1 {
		t.Errorf("merging modified the envelope default: %v", e.DefaultContext.Tags)
	}
}

func TestEffectiveObservedAt(t *testing.T) {
	collected := time.Date(2026, 8, 31, 6, 0, 0, 0, time.UTC)
	own := time.Date(2026, 8, 30, 1, 0, 0, 0, time.UTC)

	if got := (&Record{}).EffectiveObservedAt(collected); !got.Equal(collected) {
		t.Errorf("with no observed_at = %v, want the collection time %v", got, collected)
	}
	if got := (&Record{ObservedAt: &own}).EffectiveObservedAt(collected); !got.Equal(own) {
		t.Errorf("with observed_at = %v, want the record's own %v", got, own)
	}
}

func TestDateRoundTrip(t *testing.T) {
	var d Date
	if err := d.UnmarshalJSON([]byte(`"2021-06-22"`)); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if d.Year() != 2021 || d.Month() != time.June || d.Day() != 22 {
		t.Fatalf("parsed %v, want 2021-06-22", d.Time)
	}
	b, err := d.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `"2021-06-22"` {
		t.Errorf("marshalled %s, want %q", b, `"2021-06-22"`)
	}
	if err := d.UnmarshalJSON([]byte(`"22/06/2021"`)); err == nil {
		t.Error("a non-ISO date was accepted")
	}
}
