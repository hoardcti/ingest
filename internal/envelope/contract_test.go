package envelope_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/hoardcti/ingest/internal/envelope"
)

const (
	schemaPath   = "../../contract/envelope-v1.schema.json"
	examplesGlob = "../../contract/examples/*.json"
)

// compileSchema loads the published contract. Format assertions are switched on
// so that date-time and date fields are genuinely checked rather than annotated.
func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()

	f, err := os.Open(schemaPath)
	if err != nil {
		t.Fatalf("open schema: %v", err)
	}
	defer f.Close()

	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("envelope-v1.schema.json", doc); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	sch, err := c.Compile("envelope-v1.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return sch
}

func examples(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(examplesGlob)
	if err != nil {
		t.Fatalf("glob examples: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("no example envelopes found at %s; the contract has no worked examples", examplesGlob)
	}
	return paths
}

func validateAgainstSchema(t *testing.T, sch *jsonschema.Schema, name string, data []byte) {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("%s: parse JSON: %v", name, err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Errorf("%s: does not satisfy the published schema:\n%v", name, err)
	}
}

// The examples are the documentation. If they stop matching the schema, every
// collector author copying from them is being misled.
func TestExamplesMatchSchema(t *testing.T) {
	sch := compileSchema(t)
	for _, path := range examples(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			validateAgainstSchema(t, sch, filepath.Base(path), data)
		})
	}
}

// The Go validator is hand-written so it can run on the hot path, which means
// nothing structurally prevents it from drifting away from the schema. This is
// what prevents it: everything the schema accepts, the Go validator must accept.
func TestExamplesPassGoValidation(t *testing.T) {
	for _, path := range examples(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			e, err := envelope.Decode(data)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if err := envelope.Validate(e); err != nil {
				t.Errorf("Go validation rejected an envelope the schema accepts:\n%v", err)
			}
		})
	}
}

// And the other direction: whatever the Go structs produce must still satisfy
// the schema. A renamed JSON tag, a missing omitempty, or a field the structs
// have and the schema does not, all surface here.
func TestGoStructsRoundTripThroughSchema(t *testing.T) {
	sch := compileSchema(t)
	for _, path := range examples(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			e, err := envelope.Decode(data)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			out, err := json.Marshal(e)
			if err != nil {
				t.Fatalf("re-encode: %v", err)
			}
			validateAgainstSchema(t, sch, filepath.Base(path)+" (re-encoded)", out)
		})
	}
}

// Decoding must be lenient about unknown fields: a collector running a newer
// minor version of the contract has to keep working against an ingest service
// that has not been redeployed yet.
func TestDecodeIgnoresUnknownFields(t *testing.T) {
	data := []byte(`{
		"schema_version": "1.1",
		"source": "future-feed",
		"collected_at": "2026-01-01T00:00:00Z",
		"something_added_in_1_1": {"a": 1},
		"records": [
			{"kind": "indicator", "indicator": {"type": "domain", "raw_value": "evil.com"},
			 "brand_new_field": true}
		]
	}`)

	e, err := envelope.Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := envelope.Validate(e); err != nil {
		t.Fatalf("a 1.1 envelope was rejected by a 1.0 build: %v", err)
	}
	if len(e.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(e.Records))
	}
}
