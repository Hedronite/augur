// Package schema holds the A0 conformance tests. The JSON Schemas in schema/
// are the contract; these tests check that the example policy, the AM v2 input
// fixtures and the golden verdicts all agree with them.
package schema_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

const root = "../.."

type schemas struct {
	policy, input, verdict *jsonschema.Schema
}

func readFile(t *testing.T, parts ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{root}, parts...)...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(parts...), err)
	}
	return b
}

func parseJSON(t *testing.T, b []byte) any {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	return v
}

// yamlToJSONValue decodes YAML and round-trips it through encoding/json, so
// that timestamps and integers reach the validator as plain JSON values.
func yamlToJSONValue(t *testing.T, b []byte) any {
	t.Helper()
	var doc any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse YAML: %v", err)
	}
	return roundTrip(t, doc)
}

func roundTrip(t *testing.T, doc any) any {
	t.Helper()
	j, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return parseJSON(t, j)
}

func load(t *testing.T) schemas {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)

	files := []string{"policy.v0.json", "am-alerts.v2.json", "verdict.v0.json"}
	ids := map[string]string{}
	for _, f := range files {
		raw := readFile(t, "schema", f)
		doc := parseJSON(t, raw)
		m, ok := doc.(map[string]any)
		if !ok {
			t.Fatalf("%s: top level must be an object", f)
		}
		if got := m["$schema"]; got != "https://json-schema.org/draft/2020-12/schema" {
			t.Errorf("%s: $schema = %v, want draft 2020-12", f, got)
		}
		id, _ := m["$id"].(string)
		if !strings.HasPrefix(id, "https://github.com/Hedronite/augur/schema/") {
			t.Errorf("%s: $id = %q, want https://github.com/Hedronite/augur/schema/...", f, id)
		}
		if err := c.AddResource(id, doc); err != nil {
			t.Fatalf("%s: add resource: %v", f, err)
		}
		ids[f] = id
	}
	compile := func(f string) *jsonschema.Schema {
		s, err := c.Compile(ids[f])
		if err != nil {
			t.Fatalf("%s: compile: %v", f, err)
		}
		return s
	}
	return schemas{policy: compile("policy.v0.json"), input: compile("am-alerts.v2.json"), verdict: compile("verdict.v0.json")}
}

func TestSchemasCompile(t *testing.T) { load(t) }

func TestExamplePolicyConforms(t *testing.T) {
	s := load(t)
	if err := s.policy.Validate(yamlToJSONValue(t, readFile(t, "examples", "policy.yaml"))); err != nil {
		t.Fatalf("examples/policy.yaml does not conform to policy.v0.json:\n%v", err)
	}
}

// Policy strictness: unknown keys are errors, GREEN is not a valid default.
func TestPolicyIsStrict(t *testing.T) {
	s := load(t)
	base := func() map[string]any {
		var doc map[string]any
		if err := yaml.Unmarshal(readFile(t, "examples", "policy.yaml"), &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	mutations := map[string]func(map[string]any){
		"unknown top-level key": func(m map[string]any) { m["surprise"] = true },
		"default GREEN":         func(m map[string]any) { m["default"] = "GREEN" },
		"default missing":       func(m map[string]any) { delete(m, "default") },
		"wrong schema id":       func(m map[string]any) { m["schema"] = "augur.policy/v9" },
		"unknown hold kind": func(m map[string]any) {
			m["holds"] = []any{map[string]any{"id": "x", "match": map[string]any{"port": "1"}, "kind": "nope"}}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			doc := base()
			mutate(doc)
			if err := s.policy.Validate(roundTrip(t, doc)); err == nil {
				t.Errorf("policy schema accepted a policy with %s", name)
			}
		})
	}
}

func TestInputSchemaShape(t *testing.T) {
	s := load(t)
	accept := map[string]string{
		"empty array":         `[]`,
		"one alert":           `[{"labels":{"alertname":"Watchdog"},"startsAt":"2026-01-15T11:00:00.000Z","status":{"state":"active"},"fingerprint":"abc"}]`,
		"unknown alert field": `[{"labels":{"alertname":"Watchdog"},"startsAt":"2026-01-15T11:00:00.000Z","status":{"state":"active"},"brandNewField":{"x":1}}]`,
	}
	reject := map[string]string{
		"webhook v4 object":    `{"version":"4","groupKey":"{}","status":"firing","alerts":[]}`,
		"alert without labels": `[{"startsAt":"2026-01-15T11:00:00.000Z"}]`,
		"labels not an object": `[{"labels":"nope"}]`,
		"array of strings":     `["a"]`,
	}
	for name, doc := range accept {
		if err := s.input.Validate(parseJSON(t, []byte(doc))); err != nil {
			t.Errorf("input schema rejected %s: %v", name, err)
		}
	}
	for name, doc := range reject {
		if err := s.input.Validate(parseJSON(t, []byte(doc))); err == nil {
			t.Errorf("input schema accepted %s", name)
		}
	}
}

type expectedError struct {
	Exit   int    `json:"exit"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

var codePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func TestFixturesConform(t *testing.T) {
	s := load(t)
	dirs, err := os.ReadDir(filepath.Join(root, "testdata", "fixtures"))
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	index := string(readFile(t, "testdata", "fixtures", "INDEX.md"))
	n := 0
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		n++
		name := d.Name()
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(index, name) {
				t.Errorf("testdata/fixtures/INDEX.md does not mention %s", name)
			}
			fx := func(f string) string { return filepath.Join("testdata", "fixtures", name, f) }
			nowRaw := strings.TrimSpace(string(readFile(t, "testdata", "fixtures", name, "now.txt")))
			now, err := time.Parse(time.RFC3339, nowRaw)
			if err != nil {
				t.Fatalf("now.txt: %v", err)
			}
			alerts := readFile(t, "testdata", "fixtures", name, "alerts.json")
			policy := readFile(t, "testdata", "fixtures", name, "policy.yaml")

			_, errPath := os.Stat(filepath.Join(root, fx("expected_error.json")))
			_, okPath := os.Stat(filepath.Join(root, fx("expected.json")))
			hasErr, hasOK := errPath == nil, okPath == nil
			if hasErr == hasOK {
				t.Fatalf("exactly one of expected.json and expected_error.json must exist")
			}

			if hasErr {
				var e expectedError
				dec := json.NewDecoder(bytes.NewReader(readFile(t, "testdata", "fixtures", name, "expected_error.json")))
				dec.DisallowUnknownFields()
				if err := dec.Decode(&e); err != nil {
					t.Fatalf("expected_error.json: %v", err)
				}
				if e.Exit != 3 && e.Exit != 4 {
					t.Errorf("expected_error.json: exit = %d, want 3 or 4", e.Exit)
				}
				if !codePattern.MatchString(e.Code) {
					t.Errorf("expected_error.json: code %q is not a snake_case code", e.Code)
				}
				if e.Exit == 3 {
					// Input errors: the alerts file must not be a valid AM v2 array.
					if v, err := jsonschema.UnmarshalJSON(bytes.NewReader(alerts)); err == nil {
						if s.input.Validate(v) == nil {
							t.Errorf("exit-3 fixture has an alerts.json that the input schema accepts")
						}
					}
				}
				return
			}

			// A success fixture: every file must conform and agree with the others.
			if v, err := jsonschema.UnmarshalJSON(bytes.NewReader(alerts)); err != nil {
				t.Fatalf("alerts.json: %v", err)
			} else if err := s.input.Validate(v); err != nil {
				t.Errorf("alerts.json does not conform to am-alerts.v2.json:\n%v", err)
			}
			if err := s.policy.Validate(yamlToJSONValue(t, policy)); err != nil {
				t.Errorf("policy.yaml does not conform to policy.v0.json:\n%v", err)
			}
			expected := readFile(t, "testdata", "fixtures", name, "expected.json")
			if err := s.verdict.Validate(parseJSON(t, expected)); err != nil {
				t.Fatalf("expected.json does not conform to verdict.v0.json:\n%v", err)
			}

			var verdict struct {
				GeneratedAt  string `json:"generated_at"`
				TimeSource   string `json:"time_source"`
				PolicySHA256 string `json:"policy_sha256"`
				Sources      []struct {
					AlertCount int `json:"alert_count"`
				} `json:"sources"`
			}
			if err := json.Unmarshal(expected, &verdict); err != nil {
				t.Fatal(err)
			}
			if g, err := time.Parse(time.RFC3339, verdict.GeneratedAt); err != nil || !g.Equal(now) {
				t.Errorf("generated_at %q must equal now.txt %q", verdict.GeneratedAt, nowRaw)
			}
			if verdict.TimeSource != "flag" {
				t.Errorf("time_source = %q, want flag (fixtures always pass --now)", verdict.TimeSource)
			}
			sum := sha256.Sum256(policy)
			if want := hex.EncodeToString(sum[:]); verdict.PolicySHA256 != want {
				t.Errorf("policy_sha256 = %s, want %s (sha256 of policy.yaml bytes)", verdict.PolicySHA256, want)
			}
			var arr []json.RawMessage
			if err := json.Unmarshal(alerts, &arr); err == nil && len(verdict.Sources) == 1 && verdict.Sources[0].AlertCount != len(arr) {
				t.Errorf("sources[0].alert_count = %d, alerts.json has %d", verdict.Sources[0].AlertCount, len(arr))
			}
		})
	}
	if n == 0 {
		t.Fatal("no fixtures found in testdata/fixtures")
	}
}

// Verdict strictness: unknown fields and unknown reason codes are errors.
func TestVerdictIsStrict(t *testing.T) {
	s := load(t)
	dirs, _ := os.ReadDir(filepath.Join(root, "testdata", "fixtures"))
	var sample []byte
	for _, d := range dirs {
		if b, err := os.ReadFile(filepath.Join(root, "testdata", "fixtures", d.Name(), "expected.json")); err == nil {
			sample = b
			break
		}
	}
	if sample == nil {
		t.Skip("no success fixture yet")
	}
	mutations := map[string]func(map[string]any){
		"unknown top-level field": func(m map[string]any) { m["surprise"] = 1 },
		"unknown reason code":     func(m map[string]any) { m["reasons"] = []any{"made_up_reason"} },
		"bad overall":             func(m map[string]any) { m["overall"] = "ORANGE" },
		"wrong schema id":         func(m map[string]any) { m["schema"] = "augur.verdict/v9" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal(sample, &m); err != nil {
				t.Fatal(err)
			}
			mutate(m)
			if err := s.verdict.Validate(roundTrip(t, m)); err == nil {
				t.Errorf("verdict schema accepted a verdict with %s", name)
			}
		})
	}
}
