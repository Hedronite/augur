package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Hedronite/augur/internal/model"
)

const fixturesDir = "../../testdata/fixtures"

// parseOK parses and fails the test on any error.
func parseOK(t *testing.T, doc string) model.Policy {
	t.Helper()
	p, errs := Parse([]byte(doc))
	if len(errs) != 0 {
		t.Fatalf("Parse reported %d error(s): %+v", len(errs), errs)
	}
	return p
}

// paths returns the sorted, de-duplicated field paths of a Parse result.
func paths(errs []model.FieldError) []string {
	seen := make(map[string]bool, len(errs))
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		if seen[e.Path] {
			continue
		}
		seen[e.Path] = true
		out = append(out, e.Path)
	}
	sort.Strings(out)
	return out
}

// TestFixturePolicyErrors drives the exit-4 fixtures. expected_error.json's
// detail is the sorted, comma-separated list of field paths the parser must
// report, so fixture 76 asserts that validate reports every error, not just
// the first.
func TestFixturePolicyErrors(t *testing.T) {
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	ran := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(fixturesDir, e.Name(), "expected_error.json"))
		if err != nil {
			continue
		}
		var exp struct {
			Exit   int    `json:"exit"`
			Detail string `json:"detail"`
		}
		if err := json.Unmarshal(raw, &exp); err != nil {
			t.Fatalf("%s: expected_error.json: %v", e.Name(), err)
		}
		if exp.Exit != 4 {
			continue
		}
		ran++
		t.Run(e.Name(), func(t *testing.T) {
			doc, err := os.ReadFile(filepath.Join(fixturesDir, e.Name(), "policy.yaml"))
			if err != nil {
				t.Fatalf("read policy: %v", err)
			}
			p, errs := Parse(doc)
			if len(errs) == 0 {
				t.Fatal("Parse accepted a policy the fixture rejects")
			}
			if p.SHA256 != "" || p.Watchdog.AlertName != "" {
				t.Fatal("Parse returned a partial policy alongside its errors")
			}
			want := strings.Split(exp.Detail, ",")
			sort.Strings(want)
			got := paths(errs)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("reported paths %v, want %v", got, want)
			}
			for _, fe := range errs {
				if fe.Problem == "" || fe.Fix == "" {
					t.Errorf("%s: error has no problem or fix text: %+v", fe.Path, fe)
				}
				if fe.Line == 0 {
					t.Errorf("%s: error has no line number", fe.Path)
				}
			}
		})
	}
	if ran < 6 {
		t.Fatalf("only %d exit-4 fixtures exercised, expected at least 6", ran)
	}
}

// TestExamplePolicy parses the shipped example.
func TestExamplePolicy(t *testing.T) {
	doc, err := os.ReadFile("../../examples/policy.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	p := parseOK(t, string(doc))
	if p.Default != model.Yellow {
		t.Errorf("Default = %q, want YELLOW", p.Default)
	}
	if p.HostLabel != "host" || p.ReplicaLabel != "replica" {
		t.Errorf("labels = %q/%q", p.HostLabel, p.ReplicaLabel)
	}
	if p.NodeExporterRedHold != 10*time.Minute {
		t.Errorf("NodeExporterRedHold = %v, want 10m", p.NodeExporterRedHold)
	}
	if p.Watchdog.AlertName != "Watchdog" {
		t.Errorf("Watchdog.AlertName = %q", p.Watchdog.AlertName)
	}
	if len(p.Replicas) != 2 || p.Replicas[0] != "r1" || p.Replicas[1] != "r2" {
		t.Errorf("Replicas = %v, want [r1 r2]", p.Replicas)
	}
	if len(p.Rules) == 0 || len(p.Holds) == 0 {
		t.Errorf("example parsed to %d rules and %d holds", len(p.Rules), len(p.Holds))
	}
	var escalated bool
	for _, r := range p.Rules {
		if r.Escalate != nil {
			escalated = true
			if r.Escalate.After != 10*time.Minute {
				t.Errorf("escalation after = %v, want the 10m hold", r.Escalate.After)
			}
			if r.Escalate.Hosts != model.HostsFirstClass {
				t.Errorf("escalation hosts = %q", r.Escalate.Hosts)
			}
		}
	}
	if !escalated {
		t.Error("example has no escalating rule")
	}
}

// TestDefaults locks the values the parser fills in.
func TestDefaults(t *testing.T) {
	p := parseOK(t, `schema: augur.policy/v0
default: YELLOW
watchdog:
  alertname: Watchdog
rules: []
`)
	if p.HostLabel != defaultHostLabel || p.ReplicaLabel != defaultReplicaLabel {
		t.Errorf("labels = %q/%q", p.HostLabel, p.ReplicaLabel)
	}
	if p.NodeExporterRedHold != defaultRedHold {
		t.Errorf("NodeExporterRedHold = %v, want %v", p.NodeExporterRedHold, defaultRedHold)
	}
	if p.Watchdog.DeadmanWindow != defaultDeadmanWindow {
		t.Errorf("DeadmanWindow = %v, want %v", p.Watchdog.DeadmanWindow, defaultDeadmanWindow)
	}
	if p.Replicas != nil {
		t.Errorf("Replicas = %v, want nil for single-view mode", p.Replicas)
	}
	if len(p.Rules) != 0 {
		t.Errorf("Rules = %v, want none", p.Rules)
	}
}

// TestReplicasEmptyIsRejected: an explicitly empty list is a configuration
// error, not a synonym for leaving the key out.
func TestReplicasEmptyIsRejected(t *testing.T) {
	_, errs := Parse([]byte(`schema: augur.policy/v0
default: YELLOW
watchdog: {alertname: Watchdog}
replicas: []
rules: []
`))
	if len(errs) != 1 || errs[0].Path != "replicas" {
		t.Fatalf("errors = %+v, want one at replicas", errs)
	}
}

// TestMatchersAreAnchored: a regex matcher must not match a substring.
func TestMatchersAreAnchored(t *testing.T) {
	p := parseOK(t, `schema: augur.policy/v0
default: YELLOW
watchdog: {alertname: Watchdog}
rules:
  - id: disk
    match: {alertname: {regex: "host-[ab]"}}
    severity: YELLOW
`)
	m := p.Rules[0].Match["alertname"]
	if !m.Matches("host-a") || !m.Matches("host-b") {
		t.Error("anchored matcher does not match host-a or host-b")
	}
	if m.Matches("xhost-a") || m.Matches("host-a2") {
		t.Error("matcher is not anchored")
	}
}

// TestEscalateKeywordResolves: after: node_exporter_red_hold resolves from the
// top-level key even when that key appears after the rules.
func TestEscalateKeywordResolves(t *testing.T) {
	for _, doc := range []string{
		`schema: augur.policy/v0
default: YELLOW
watchdog: {alertname: Watchdog}
node_exporter_red_hold: 3m
rules:
  - id: ne
    match: {alertname: NodeExporterDown}
    severity: YELLOW
    escalate: {to: RED, after: node_exporter_red_hold, hosts: first_class}
`,
		`schema: augur.policy/v0
default: YELLOW
watchdog: {alertname: Watchdog}
rules:
  - id: ne
    match: {alertname: NodeExporterDown}
    severity: YELLOW
    escalate: {to: RED, after: node_exporter_red_hold, hosts: first_class}
node_exporter_red_hold: 3m
`,
	} {
		p := parseOK(t, doc)
		if got := p.Rules[0].Escalate.After; got != 3*time.Minute {
			t.Fatalf("After = %v, want 3m whichever order the keys appear in", got)
		}
	}
}

// TestSHA256IsTheDigestOfTheBytes: the verdict quotes it, so it must be of the
// exact input.
func TestSHA256IsTheDigestOfTheBytes(t *testing.T) {
	doc := []byte(`schema: augur.policy/v0
default: RED
watchdog: {alertname: Watchdog}
rules: []
`)
	p := parseOK(t, string(doc))
	sum := sha256.Sum256(doc)
	if p.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("SHA256 = %q", p.SHA256)
	}
	// A comment changes the digest but not the meaning: the verdict still
	// names the bytes that were evaluated.
	p2 := parseOK(t, string(doc)+"# trailing comment\n")
	if p2.SHA256 == p.SHA256 {
		t.Fatal("SHA256 ignored a change in the bytes")
	}
}

// TestCollectsEveryError is the behaviour fixture 76 stands for: one pass
// reports every problem, so validate is useful in one run.
func TestCollectsEveryError(t *testing.T) {
	_, errs := Parse([]byte(`schema: augur.policy/v9
default: GREEN
host_label: ""
node_exporter_red_hold: "10 minutes"
first_class_hosts: [Host_A]
surprise: true
rules:
  - id: Bad_ID
    match: {}
    severity: GREEN
  - id: dup
    match: {alertname: A}
    severity: YELLOW
  - id: dup
    match: {alertname: B}
    severity: YELLOW
holds:
  - id: h
    match: {port: "6443"}
    kind: invented
`))
	got := paths(errs)
	want := []string{
		"default", "first_class_hosts[0]", "host_label",
		"holds[0].kind", "node_exporter_red_hold", "rules[0].id",
		"rules[0].match", "rules[0].severity", "rules[2].id", "schema",
		"surprise",
	}
	for _, w := range want {
		if !contains(got, w) {
			t.Errorf("missing error at %q; got %v", w, got)
		}
	}
	if len(errs) < len(want) {
		t.Errorf("reported %d errors, want at least %d", len(errs), len(want))
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// TestHoldsRules covers the conditional expires_at rules and the kind enum.
func TestHoldsRules(t *testing.T) {
	base := `schema: augur.policy/v0
default: YELLOW
watchdog: {alertname: Watchdog}
rules: []
holds:
`
	cases := map[string]struct {
		body string
		path string
	}{
		"announced dark without expiry": {"  - id: a\n    match: {host: host-a}\n    kind: announced_dark\n", "holds[0].expires_at"},
		"expected dark with expiry":     {"  - id: a\n    match: {port: \"6443\"}\n    kind: expected_dark\n    expires_at: 2026-12-01T00:00:00Z\n", "holds[0].expires_at"},
		"expiry is not a time":          {"  - id: a\n    match: {host: host-a}\n    kind: announced_dark\n    expires_at: soon\n", "holds[0].expires_at"},
		"unknown kind":                  {"  - id: a\n    match: {host: host-a}\n    kind: maybe\n", "holds[0].kind"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, errs := Parse([]byte(base + tc.body))
			if len(errs) == 0 || !contains(paths(errs), tc.path) {
				t.Fatalf("errors = %+v, want one at %s", errs, tc.path)
			}
		})
	}
	t.Run("announced dark parses", func(t *testing.T) {
		p := parseOK(t, base+"  - id: a\n    match: {host: host-a}\n    kind: announced_dark\n    expires_at: 2026-12-01T00:00:00Z\n")
		want := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
		if !p.Holds[0].ExpiresAt.Equal(want) {
			t.Fatalf("ExpiresAt = %v, want %v", p.Holds[0].ExpiresAt, want)
		}
	})
}

// TestNotYAML is the "not the policy's fault" branch: it still exits 4, with a
// line number and no panic.
func TestNotYAML(t *testing.T) {
	_, errs := Parse([]byte("default: [unclosed\n"))
	if len(errs) == 0 {
		t.Fatal("Parse accepted invalid YAML")
	}
	if errs[0].Problem == "" || errs[0].Fix == "" {
		t.Errorf("error has no problem or fix text: %+v", errs[0])
	}
	_, errs = Parse(nil)
	if len(errs) == 0 {
		t.Fatal("Parse accepted an empty document")
	}
}

// TestValueIsBounded keeps the parser from holding an unbounded excerpt.
func TestValueIsBounded(t *testing.T) {
	long := strings.Repeat("z", 1000)
	_, errs := Parse([]byte("schema: augur.policy/v0\ndefault: " + long + "\n"))
	if len(errs) == 0 {
		t.Fatal("Parse accepted a bad default")
	}
	if len(errs[0].Value) > maxValueBytes {
		t.Fatalf("Value is %d bytes, want at most %d", len(errs[0].Value), maxValueBytes)
	}
}

// TestNonStringScalars: a value that reaches JSON as null or a number is not a
// string, so the schema refuses it wherever it says type: string. The matcher
// case is the fuzz finding: `match:\n  port:\n` leaves a null value.
func TestNonStringScalars(t *testing.T) {
	head := "schema: augur.policy/v0\ndefault: YELLOW\n"
	build := func(body string) string {
		if strings.Contains(body, "watchdog:") {
			return head + body
		}
		return head + "watchdog: {alertname: Watchdog}\n" + body
	}
	reject := map[string]struct{ body, path string }{
		"null matcher value": {
			"rules:\n  - id: r\n    match:\n      port:\n    severity: YELLOW\n",
			"rules[0].match.port",
		},
		"number matcher value": {
			"rules:\n  - id: r\n    match: {port: 6443}\n    severity: YELLOW\n",
			"rules[0].match.port",
		},
		"boolean matcher value": {
			"rules:\n  - id: r\n    match: {host: true}\n    severity: YELLOW\n",
			"rules[0].match.host",
		},
		"null matcher value in a hold": {
			"rules: []\nholds:\n  - id: h\n    match:\n      host:\n    kind: expected_dark\n",
			"holds[0].match.host",
		},
		"number rule id": {
			"rules:\n  - id: 123\n    match: {alertname: A}\n    severity: YELLOW\n",
			"rules[0].id",
		},
		"number hold id": {
			"rules: []\nholds:\n  - id: 123\n    match: {host: host-a}\n    kind: known_hold\n",
			"holds[0].id",
		},
		"number host_label":         {"host_label: 5\nrules: []\n", "host_label"},
		"number watchdog alertname": {"watchdog: {alertname: 5}\nrules: []\n", "watchdog.alertname"},
		"number replica slug":       {"replicas: [123]\nrules: []\n", "replicas[0]"},
		"number host slug":          {"first_class_hosts: [123]\nrules: []\n", "first_class_hosts[0]"},
		"empty replica entry":       {"replicas:\n  -\nrules: []\n", "replicas[0]"},
		"number regex": {
			"rules:\n  - id: r\n    match: {alertname: {regex: 5}}\n    severity: YELLOW\n",
			"rules[0].match.alertname.regex",
		},
	}
	for name, tc := range reject {
		t.Run(name, func(t *testing.T) {
			_, errs := Parse([]byte(build(tc.body)))
			if len(errs) == 0 || !contains(paths(errs), tc.path) {
				t.Fatalf("errors = %+v, want one at %s", errs, tc.path)
			}
		})
	}

	accept := map[string]string{
		"quoted number matcher":  "rules:\n  - id: r\n    match: {port: \"6443\"}\n    severity: YELLOW\n",
		"bare word matcher":      "rules:\n  - id: r\n    match: {alertname: Watchdog}\n    severity: YELLOW\n",
		"empty string matcher":   "rules:\n  - id: r\n    match: {host: \"\"}\n    severity: YELLOW\n",
		"timestamp matcher":      "rules:\n  - id: r\n    match: {since: 2026-01-15T00:00:00Z}\n    severity: YELLOW\n",
		"quoted numeric rule id": "rules:\n  - id: \"123\"\n    match: {alertname: A}\n    severity: YELLOW\n",
	}
	for name, body := range accept {
		t.Run("accepts "+name, func(t *testing.T) {
			parseOK(t, build(body))
		})
	}
}

// TestSlugRejectsLeadingDash: a host or replica slug may not start with a
// hyphen, matching Vigil's slug pattern. A host label that starts with one is
// reported as `unmapped` by the engine; in a policy it is a field error.
func TestSlugRejectsLeadingDash(t *testing.T) {
	head := "schema: augur.policy/v0\ndefault: YELLOW\nwatchdog: {alertname: Watchdog}\n"
	reject := map[string]struct{ body, path string }{
		"leading dash in first_class_hosts": {
			"first_class_hosts: [-host-a]\nrules: []\n", "first_class_hosts[0]",
		},
		"leading dash in replicas": {
			"replicas: [-host-a]\nrules: []\n", "replicas[0]",
		},
	}
	for name, tc := range reject {
		t.Run(name, func(t *testing.T) {
			_, errs := Parse([]byte(head + tc.body))
			if len(errs) == 0 || !contains(paths(errs), tc.path) {
				t.Fatalf("errors = %+v, want one at %s", errs, tc.path)
			}
		})
	}
	// The pattern forbids a leading hyphen only: a trailing one is still a slug.
	t.Run("trailing dash is still a slug", func(t *testing.T) {
		parseOK(t, head+"replicas: [host-, r1]\nrules: []\n")
	})
}

// TestRefusedYAMLFeatures: a policy is data an operator reviews, so the YAML
// features that hide it from review are refused. JSON Schema cannot see any of
// these, so the differential harness refuses the same documents through
// strictParse; these rows and the seeds keep the two sides locked together.
func TestRefusedYAMLFeatures(t *testing.T) {
	const head = "schema: augur.policy/v0\ndefault: YELLOW\nwatchdog: {alertname: Watchdog}\nrules: []\n"
	refuse := map[string]struct{ doc, path, problem string }{
		"custom tag": {
			"schema: augur.policy/v0\ndefault: YELLOW\nwatchdog:\n  alertname: !0 0\nrules: []\n",
			"watchdog.alertname", "!0",
		},
		// A core tag is judged by the field it lands on, not by the feature gate:
		// !!int passes the gate and then fails the string check for alertname.
		"explicit retyping tag": {
			"schema: augur.policy/v0\ndefault: YELLOW\nwatchdog:\n  alertname: !!int 5\nrules: []\n",
			"watchdog.alertname", "must be a string",
		},
		"anchor": {
			head + "first_class_hosts: &h [host-a]\n",
			"first_class_hosts", "anchors are not allowed",
		},
		// An alias needs an anchor defined earlier in the document, and the walk
		// reports the first offending feature, so the anchor is what surfaces.
		"alias": {
			head + "first_class_hosts: &h [host-a]\nreplicas: *h\n",
			"first_class_hosts", "anchors are not allowed",
		},
		"merge key": {
			"schema: augur.policy/v0\ndefault: YELLOW\nwatchdog:\n  <<: {alertname: Watchdog}\nrules: []\n",
			"watchdog.<<", "merge keys are not allowed",
		},
		"duplicate key": {
			"schema: augur.policy/v0\ndefault: YELLOW\ndefault: RED\nwatchdog: {alertname: Watchdog}\nrules: []\n",
			"default", "duplicate key",
		},
		"second document": {
			head + "---\nschema: augur.policy/v0\n",
			"", "second YAML document",
		},
	}
	for name, tc := range refuse {
		t.Run(name, func(t *testing.T) {
			_, errs := Parse([]byte(tc.doc))
			if len(errs) == 0 {
				t.Fatalf("Parse accepted a policy with a %s", name)
			}
			if errs[0].Path != tc.path && !(tc.path == "" && errs[0].Path == "") {
				t.Fatalf("Path = %q, want %q", errs[0].Path, tc.path)
			}
			if !strings.Contains(errs[0].Problem, tc.problem) {
				t.Fatalf("Problem = %q, want it to mention %q", errs[0].Problem, tc.problem)
			}
			if errs[0].Fix == "" {
				t.Fatal("error has no fix text")
			}
		})
	}

	// !!timestamp is a core tag and the resolver assigns it to an unquoted
	// RFC3339 value, which the shipped policies use for expires_at.
	accept := map[string]string{
		"unquoted expires_at": head + "holds:\n  - id: m\n    match: {host: host-a}\n" +
			"    kind: announced_dark\n    expires_at: 2026-12-01T00:00:00Z\n",
		"quoted expires_at": head + "holds:\n  - id: m\n    match: {host: host-a}\n" +
			"    kind: announced_dark\n    expires_at: \"2026-12-01T00:00:00Z\"\n",
	}
	for name, doc := range accept {
		t.Run("accepts "+name, func(t *testing.T) { parseOK(t, doc) })
	}
}
