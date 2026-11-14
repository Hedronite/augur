package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"

	"github.com/Hedronite/augur/internal/model"
)

// compilePolicySchema compiles schema/policy.v0.json with format assertion on,
// so that expires_at is checked exactly as parseDateTime checks it.
func compilePolicySchema(tb testing.TB) *jsonschema.Schema {
	tb.Helper()
	raw, err := os.ReadFile("../../schema/policy.v0.json")
	if err != nil {
		tb.Fatalf("read policy schema: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		tb.Fatalf("parse policy schema: %v", err)
	}
	obj, ok := doc.(map[string]any)
	if !ok {
		tb.Fatal("policy schema is not an object")
	}
	id, _ := obj["$id"].(string)
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	if err := c.AddResource(id, doc); err != nil {
		tb.Fatalf("add policy schema: %v", err)
	}
	s, err := c.Compile(id)
	if err != nil {
		tb.Fatalf("compile policy schema: %v", err)
	}
	return s
}

// schemaAcceptsPolicy converts the YAML to the JSON value the schema sees and
// reports whether it conforms. checkable is false when the document cannot be
// expressed as JSON at all (non-string keys), which the schema cannot judge.
func schemaAcceptsPolicy(sch *jsonschema.Schema, doc []byte) (ok, checkable bool) {
	// JSON Schema cannot see YAML features. Parse refuses anchors, aliases,
	// merge keys, duplicate keys, a second document and any non-core tag, so the
	// harness refuses them too: otherwise the two sides would disagree on
	// documents that are only invalid as YAML.
	if _, fe := strictParse(doc); fe != nil {
		return false, true
	}
	var v any
	if err := yaml.Unmarshal(doc, &v); err != nil {
		return false, true
	}
	j, err := json.Marshal(v)
	if err != nil {
		return false, false
	}
	jv, err := jsonschema.UnmarshalJSON(bytes.NewReader(j))
	if err != nil {
		return false, false
	}
	return sch.Validate(jv) == nil, true
}

// seedPolicyCorpus adds every fixture policy plus the shipped example.
func seedPolicyCorpus(f *testing.F) {
	f.Helper()
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		f.Fatalf("read fixtures: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(fixturesDir, e.Name(), "policy.yaml"))
		if err != nil {
			f.Fatalf("read fixtures/%s/policy.yaml: %v", e.Name(), err)
		}
		f.Add(b)
	}
	if b, err := os.ReadFile("../../examples/policy.yaml"); err == nil {
		f.Add(b)
	}
	// One seed per YAML feature a policy may not use. Parse refuses each, and the
	// harness mirrors it, so the differential exercises both sides.
	base := "schema: augur.policy/v0\ndefault: YELLOW\nwatchdog: {alertname: Watchdog}\nrules: []\n"
	for _, extra := range []string{
		"watchdog:\n  alertname: !0 0\n",                 // custom tag
		"watchdog:\n  alertname: !!int 5\n",              // core tag that retypes a string field
		"first_class_hosts: &h [host-a]\n",               // anchor
		"first_class_hosts: &h [host-a]\nreplicas: *h\n", // alias
		"watchdog:\n  <<: {alertname: Watchdog}\n",       // merge key
		"default: RED\n",                                 // duplicate key
		"---\nschema: augur.policy/v0\n",                 // second document
		"---\nbad: [\n",                                  // trailing document that does not parse
	} {
		f.Add([]byte(base + extra))
	}
	// The input CI reported, verbatim: a custom !0 tag on alertname.
	f.Add([]byte("schema: augur.policy/v0\ndefault: YELLOW\n#000000000000000\nwatchdog:\n" +
		"  alertname: !0 0\nrules:\n  - id: a\n    match:\n     0: 0A\n    severity: YELLOW\n"))

	// The schema's date-time pattern rejects this expires_at; the parser must
	// reject it too. Kept as a seed after the pattern landed.
	f.Add([]byte(`schema: augur.policy/v0
default: YELLOW
watchdog: {alertname: Watchdog}
rules: []
holds:
  - id: maint
    match: {host: host-a}
    kind: announced_dark
    expires_at: 2025-12-01T+0:00:00Z
`))
}

// FuzzPolicyParse checks the parser never panics, that a successful parse
// yields a usable policy, and that reported errors carry the text the renderer
// needs.
func FuzzPolicyParse(f *testing.F) {
	seedPolicyCorpus(f)
	f.Fuzz(func(t *testing.T, doc []byte) {
		p, errs := Parse(doc)
		if len(errs) > 0 {
			if p.SHA256 != "" || p.Default != "" {
				t.Fatal("Parse returned a partial policy alongside its errors")
			}
			for _, e := range errs {
				if e.Problem == "" || e.Fix == "" {
					t.Fatalf("error without problem or fix: %+v", e)
				}
				if len(e.Value) > maxValueBytes {
					t.Fatalf("error value is %d bytes, want at most %d", len(e.Value), maxValueBytes)
				}
			}
			return
		}
		if p.Default != "YELLOW" && p.Default != "RED" {
			t.Fatalf("Default = %q", p.Default)
		}
		if p.Watchdog.AlertName == "" {
			t.Fatal("valid policy has no watchdog alert name")
		}
		if p.HostLabel == "" || p.ReplicaLabel == "" {
			t.Fatalf("labels = %q/%q", p.HostLabel, p.ReplicaLabel)
		}
		for _, r := range p.Rules {
			if r.Severity != "YELLOW" && r.Severity != "RED" {
				t.Fatalf("rule %s has severity %q", r.ID, r.Severity)
			}
			if len(r.Match) == 0 {
				t.Fatalf("rule %s has an empty match", r.ID)
			}
		}
		for _, h := range p.Holds {
			if h.Kind != "expected_dark" && h.Kind != "known_hold" && h.Kind != "announced_dark" {
				t.Fatalf("hold %s has kind %q", h.ID, h.Kind)
			}
		}
	})
}

// FuzzPolicySchema is the differential. JSON Schema cannot express two things
// the parser must still catch, and they are the only sanctioned divergences: a
// regex that does not compile, and a duplicate id. Everything else must agree.
func FuzzPolicySchema(f *testing.F) {
	sch := compilePolicySchema(f)
	seedPolicyCorpus(f)
	f.Fuzz(func(t *testing.T, doc []byte) {
		if len(doc) > 1<<20 {
			return
		}
		schemaOK, checkable := schemaAcceptsPolicy(sch, doc)
		if !checkable {
			return
		}
		_, errs := Parse(doc)
		parseOK := len(errs) == 0
		switch {
		case parseOK && !schemaOK:
			t.Fatalf("Parse accepted a policy the schema rejects: %q", doc)
		case schemaOK && !parseOK:
			for _, e := range errs {
				if schemaInvisible(e) {
					continue
				}
				t.Fatalf("schema accepts but Parse rejects %q at %q: %s", doc, e.Path, e.Problem)
			}
		}
	})
}

// schemaInvisible reports whether a parse error is one the policy schema cannot
// see: a pattern that does not compile, or a duplicate id.
func schemaInvisible(e model.FieldError) bool {
	if strings.HasSuffix(e.Path, ".regex") {
		return true
	}
	return strings.Contains(e.Problem, "duplicate")
}

// TestDifferentialExample runs the differential over the shipped policy and
// every fixture policy that is meant to be valid.
func TestDifferentialExample(t *testing.T) {
	sch := compilePolicySchema(t)
	docs := map[string]string{}
	if b, err := os.ReadFile("../../examples/policy.yaml"); err == nil {
		docs["examples/policy.yaml"] = string(b)
	}
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(fixturesDir, e.Name(), "expected.json")); err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(fixturesDir, e.Name(), "policy.yaml"))
		if err != nil {
			t.Fatalf("read policy: %v", err)
		}
		docs["fixtures/"+e.Name()] = string(b)
	}
	for name, doc := range docs {
		ok, checkable := schemaAcceptsPolicy(sch, []byte(doc))
		if !checkable {
			t.Errorf("%s: policy could not be expressed as JSON", name)
			continue
		}
		if !ok {
			t.Errorf("%s: policy does not conform to policy.v0.json", name)
		}
		if _, errs := Parse([]byte(doc)); len(errs) != 0 {
			t.Errorf("%s: Parse reported %d error(s): %+v", name, len(errs), errs)
		}
	}
}
