package decode

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/Hedronite/augur/internal/model"
)

// compileInputSchema compiles schema/am-alerts.v2.json with format assertion
// on.
//
// The repo's conformance compiler leaves formats unasserted, so the schema on
// its own accepts "garbage" for startsAt. Asserting the format is what makes
// the differential meaningful; the decoder is the stricter of the two under
// either compiler, which is the fail-closed direction (see TestTimestamps).
func compileInputSchema(tb testing.TB) *jsonschema.Schema {
	tb.Helper()
	raw, err := os.ReadFile("../../schema/am-alerts.v2.json")
	if err != nil {
		tb.Fatalf("read input schema: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		tb.Fatalf("parse input schema: %v", err)
	}
	obj, ok := doc.(map[string]any)
	if !ok {
		tb.Fatal("input schema is not an object")
	}
	id, _ := obj["$id"].(string)
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	if err := c.AddResource(id, doc); err != nil {
		tb.Fatalf("add input schema: %v", err)
	}
	s, err := c.Compile(id)
	if err != nil {
		tb.Fatalf("compile input schema: %v", err)
	}
	return s
}

// schemaAccepts reports whether the input schema accepts data.
func schemaAccepts(sch *jsonschema.Schema, data []byte) bool {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return false
	}
	return sch.Validate(v) == nil
}

// seedFixtures adds every fixture's alerts document to the corpus, plus the two
// rejected payload shapes.
func seedFixtures(f *testing.F) {
	f.Helper()
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		f.Fatalf("read fixtures: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(fixturesDir, e.Name(), "alerts.json"))
		if err != nil {
			f.Fatalf("read fixtures/%s/alerts.json: %v", e.Name(), err)
		}
		f.Add(b)
	}
	// Keys are matched exactly, as the schema matches them. A mixed-case key on
	// its own leaves "startsAt" missing, which the schema rejects; a mixed-case
	// key beside the real one is an unknown field the schema accepts, so the
	// decoder must ignore it even when its value is the wrong type. Both were
	// once read as their lower-case twin by encoding/json.
	f.Add([]byte(`[{"labels":{"alertname":"Watchdog","host":"host-a"},` +
		`"StartsAt":"2026-01-15T11:00:00Z","status":{"state":"active"}}]`))
	f.Add([]byte(`[{"labels":{"alertname":"NodeExporterDown","host":"host-a"},` +
		`"startsAt":"2026-01-15T11:45:00Z","STARTSAT":{"nope":1},` +
		`"status":{"state":"active"},"STATUS":{"state":"not-a-state"}}]`))

	// The schema's date-time pattern rejects this; the decoder must too, or the
	// differential fails. Kept as a seed after the pattern landed.
	f.Add([]byte(`[{"labels":{"alertname":"Watchdog","host":"host-a"},` +
		`"startsAt":"2025-12-01T+0:00:00Z","status":{"state":"active"}}]`))
	f.Add([]byte(`{"version":"4","groupKey":"{}","status":"firing","alerts":[]}`))
	f.Add([]byte(`{"receiver":"x","status":"firing","alerts":[{"status":"firing","valueString":"v"}]}`))
}

// FuzzDecodeAM checks the decoder never panics, is deterministic, and keeps
// every output string inside its bound.
func FuzzDecodeAM(f *testing.F) {
	seedFixtures(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		first, err := DecodeAM(data)
		second, err2 := DecodeAM(data)
		if (err == nil) != (err2 == nil) {
			t.Fatalf("non-deterministic result: %v then %v", err, err2)
		}
		if err != nil {
			if err.Error() != err2.Error() {
				t.Fatalf("non-deterministic error: %v then %v", err, err2)
			}
			return
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatal("decoding the same bytes twice gave different snapshots")
		}
		for _, a := range first.Alerts {
			if a.Name != model.Unnamed && !model.NamePattern.MatchString(a.Name) {
				t.Fatalf("name %q is outside its bound", a.Name)
			}
			if a.SourceSeverity != nil && !model.SeverityLabelPattern.MatchString(*a.SourceSeverity) {
				t.Fatalf("source_severity %q is outside its bound", *a.SourceSeverity)
			}
			switch a.State {
			case model.StateActive, model.StateSilenced, model.StateInhibited, model.StateUnprocessed:
			default:
				t.Fatalf("unknown alert state %q", a.State)
			}
		}
	})
}

// FuzzSniff checks Sniff never panics, only ever returns *ErrMalformed for
// bytes it cannot classify, and never contradicts DecodeAM about an
// Alertmanager array.
func FuzzSniff(f *testing.F) {
	seedFixtures(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		kind, err := Sniff(data)
		if err != nil {
			var em *ErrMalformed
			if !errors.As(err, &em) {
				t.Fatalf("Sniff returned %T, want *ErrMalformed", err)
			}
			return
		}
		switch kind {
		case KindAMv2, KindAMWebhookV4, KindGrafana, KindUnknown:
		default:
			t.Fatalf("Sniff returned an unknown kind %q", kind)
		}
		if kind != KindAMv2 {
			return
		}
		if _, derr := DecodeAM(data); derr != nil {
			var eu *ErrUnsupported
			if errors.As(derr, &eu) {
				t.Fatalf("Sniff said %q but DecodeAM refused it as unsupported", kind)
			}
		}
	})
}

// FuzzDecodeAMSchema is the differential: for any input, the schema's verdict
// and the decoder's must be the same, except for the two documented DoS caps
// that sit above the schema's contract.
func FuzzDecodeAMSchema(f *testing.F) {
	sch := compileInputSchema(f)
	seedFixtures(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		schemaOK := schemaAccepts(sch, data)
		_, derr := DecodeAM(data)
		decOK := derr == nil
		if schemaOK == decOK {
			return
		}
		if schemaOK && exceedCap(derr) {
			return
		}
		t.Fatalf("schema accepts=%v, decoder accepts=%v: input %q, err %v", schemaOK, decOK, data, derr)
	})
}

// exceedCap reports the sanctioned divergences: the DoS caps, which the schema
// does not carry.
func exceedCap(err error) bool {
	var em *ErrMalformed
	if !errors.As(err, &em) {
		return false
	}
	return em.Detail == "too many alerts" || em.Detail == "alerts[0].labels: too many labels"
}

// TestDifferentialFixtures runs the differential over every fixture input, so
// a regression shows up without waiting for the fuzzer.
func TestDifferentialFixtures(t *testing.T) {
	sch := compileInputSchema(t)
	for _, fx := range loadFixtures(t) {
		// The exit-3 fixtures are deliberately outside the schema: that is what
		// the conformance test checks for them.
		if fx.expErr != nil {
			continue
		}
		if !schemaAccepts(sch, fx.alerts) {
			t.Errorf("%s: fixture input does not conform to the input schema", fx.name)
		}
	}
}

// TestSchemaRejectsWhatDecodeRejects is the converse sanity check on a handful
// of shapes, so the differential has a human-readable twin.
func TestSchemaRejectsWhatDecodeRejects(t *testing.T) {
	sch := compileInputSchema(t)
	bodies := map[string]string{
		"missing labels":   `[{"startsAt":"2026-01-15T11:00:00Z","status":{"state":"active"}}]`,
		"missing status":   `[{"labels":{"alertname":"W"},"startsAt":"2026-01-15T11:00:00Z"}]`,
		"labels not a map": `[{"labels":"nope","startsAt":"2026-01-15T11:00:00Z","status":{"state":"active"}}]`,
		"unknown state":    `[{"labels":{"alertname":"W"},"startsAt":"2026-01-15T11:00:00Z","status":{"state":"firing"}}]`,
		"bad start":        `[{"labels":{"alertname":"W"},"startsAt":"garbage","status":{"state":"active"}}]`,
		"not an array":     `{"alerts":[]}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			if schemaAccepts(sch, []byte(body)) {
				t.Fatal("input schema accepted a body it should reject")
			}
			if _, err := DecodeAM([]byte(body)); err == nil {
				t.Fatal("DecodeAM accepted a body it should reject")
			}
		})
	}
}
