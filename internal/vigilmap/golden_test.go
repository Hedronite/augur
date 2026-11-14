package vigilmap_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/Hedronite/augur/internal/model"
	"github.com/Hedronite/augur/internal/render"
	"github.com/Hedronite/augur/internal/vigilmap"
)

var update = flag.Bool("update", false, "rewrite the goldens under testdata/vigil from the sources")

const (
	root       = "../.."
	vigilRoot  = root + "/testdata/vigil"
	vigilURL   = "https://github.com/Hedronite/vigil/schema/vigil.summary.v0.schema.json"
	blockURL   = "https://github.com/Hedronite/augur/schema/vigil-block.v0.json"
	verdictURL = "https://github.com/Hedronite/augur/schema/verdict.v0.json"
)

func read(t testing.TB, path ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(path...))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parse(t testing.TB, b []byte) any {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type schemas struct {
	verdict, block, vigil, vigilVerdict *jsonschema.Schema
}

func loadSchemas(t testing.TB) schemas {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	add := func(url string, b []byte) {
		if err := c.AddResource(url, parse(t, b)); err != nil {
			t.Fatal(err)
		}
	}
	add(verdictURL, read(t, root, "schema", "verdict.v0.json"))
	add(blockURL, read(t, root, "schema", "vigil-block.v0.json"))
	add(vigilURL, read(t, vigilRoot, "vendor", "vigil.summary.v0.schema.json"))
	compile := func(url string) *jsonschema.Schema {
		s, err := c.Compile(url)
		if err != nil {
			t.Fatalf("compile %s: %v", url, err)
		}
		return s
	}
	return schemas{verdict: compile(verdictURL), block: compile(blockURL), vigil: compile(vigilURL), vigilVerdict: compile(vigilURL + "#/$defs/verdict")}
}

// TestVigilVendoredSchemaDigest keeps the vendored copy honest: its digest is
// pinned in SOURCE next to the Vigil commit it came from.
func TestVigilVendoredSchemaDigest(t *testing.T) {
	sum := sha256.Sum256(read(t, vigilRoot, "vendor", "vigil.summary.v0.schema.json"))
	got := hex.EncodeToString(sum[:])
	source := string(read(t, vigilRoot, "vendor", "SOURCE"))
	if !strings.Contains(source, "sha256: "+got) {
		t.Fatalf("vendored schema digest %s is not the one pinned in SOURCE", got)
	}
	if !strings.Contains(source, "commit: ") || !strings.Contains(source, "repository: Hedronite/vigil") {
		t.Fatal("SOURCE must name the Vigil repository and commit")
	}
}

// A golden case: where its verdict comes from.
type goldenCase struct {
	name    string
	fixture string               // a fixture directory whose expected.json is the verdict
	build   func() model.Verdict // or a synthetic verdict
}

var cases = []goldenCase{
	{name: "green-watchdog-only", fixture: "10-watchdog-only"},
	{name: "empty-array-watchdog-missing", fixture: "12-empty-array"},
	{name: "yellow-one-alert", fixture: "42-node-exporter-before-hold"},
	{name: "red-escalated", fixture: "50-node-exporter-past-hold-single-view"},
	{name: "held-only", fixture: "20-expected-dark-port"},
	{name: "suppressed-only", fixture: "30-silenced-alert"},
	{name: "two-replicas-split", fixture: "54-node-exporter-declared-replica-silent"},
	{name: "unmapped-host", fixture: "61-unmapped-host"},
	{name: "blind-unreachable", build: blindUnreachable},
	{name: "stale-source", build: staleSource},
	{name: "truncated", build: truncated},
	{name: "unnamed-name", build: unnamedName},
}

var (
	at     = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	digest = func() string {
		s := sha256.Sum256([]byte("augur vigil golden policy"))
		return hex.EncodeToString(s[:])
	}()
)

func base() model.Verdict {
	last := at.Add(-2 * time.Minute)
	return model.Verdict{
		APIVersion: model.VerdictAPIVersion, GeneratedAt: at, TimeSource: model.TimeWall,
		PolicySHA256: digest, Reasons: []model.Reason{},
		Watchdog: model.WatchdogState{Seen: true, LastSeen: &last},
		Sources:  []model.Source{{ID: "alertmanager", State: model.SourceOK, LastOK: &at, AlertCount: 1}},
	}
}

func heartbeat() model.VerdictAlert {
	return model.VerdictAlert{
		Name: "Watchdog", Host: "host-a", Severity: model.Green, Expected: true, Status: model.StatusActive,
		StartsAt: at.Add(-24 * time.Hour), Replicas: []string{}, Reasons: []model.Reason{model.ReasonHeartbeat},
	}
}

func rule(id string) *string { return &id }

// Alertmanager unreachable past the dead-man window: RED, no alerts, last_ok set.
func blindUnreachable() model.Verdict {
	v := base()
	last := at.Add(-6 * time.Minute)
	v.Overall = model.Red
	v.Reasons = []model.Reason{model.ReasonAlertmanagerUnreachable, model.ReasonObservabilityBlind, model.ReasonWatchdogMissing}
	v.Watchdog = model.WatchdogState{}
	v.Sources = []model.Source{{ID: "alertmanager", State: model.SourceUnreachable, LastOK: &last, AlertCount: 0}}
	v.Alerts = []model.VerdictAlert{}
	return v
}

// Alertmanager answers but its Watchdog is old: stale, YELLOW, one peer alert.
func staleSource() model.Verdict {
	v := base()
	v.Overall = model.Yellow
	v.Reasons = []model.Reason{model.ReasonAlertmanagerStale, model.ReasonWatchdogMissing}
	v.Watchdog = model.WatchdogState{}
	v.Sources = []model.Source{{ID: "alertmanager", State: model.SourceStale, LastOK: &at, AlertCount: 2}}
	v.Alerts = []model.VerdictAlert{{
		Name: "PeerPrometheusDown", Host: "host-b", Severity: model.Yellow, Status: model.StatusActive,
		StartsAt: at.Add(-40 * time.Minute), Replicas: []string{}, RuleID: rule("peer-prom-down"),
		Reasons: []model.Reason{model.ReasonRuleMatched},
	}}
	return v
}

// Sixty raising alerts (five RED that started later than most YELLOW ones) and
// the heartbeat: the block lists 50, RED first, and omits ten.
func truncated() model.Verdict {
	v := base()
	v.Overall = model.Red
	hosts := []string{"host-a", "host-b", "host-c", "host-d", "host-e"}
	var as []model.VerdictAlert
	for i := 0; i < 60; i++ {
		a := model.VerdictAlert{
			Name: fmt.Sprintf("Synthetic%02d", i), Host: hosts[i%len(hosts)], Status: model.StatusActive,
			StartsAt: at.Add(-time.Duration(120-i) * time.Minute), Replicas: []string{},
			Severity: model.Yellow, RuleID: rule("synthetic"), Reasons: []model.Reason{model.ReasonRuleMatched},
		}
		if i >= 55 {
			a.Severity = model.Red // the five newest
		}
		as = append(as, a)
	}
	as = append(as, heartbeat())
	sort.Slice(as, func(i, j int) bool {
		if as[i].Host != as[j].Host {
			return as[i].Host < as[j].Host
		}
		if as[i].Name != as[j].Name {
			return as[i].Name < as[j].Name
		}
		return as[i].StartsAt.Before(as[j].StartsAt)
	})
	v.Alerts = as
	v.Sources[0].AlertCount = len(as)
	return v
}

// A name that failed its bound and a host that failed the slug: both are
// reported as literals and survive the mapping.
func unnamedName() model.Verdict {
	v := base()
	v.Overall = model.Yellow
	v.Alerts = []model.VerdictAlert{
		{
			Name: model.Unnamed, Host: model.Unmapped, Severity: model.Yellow, Status: model.StatusActive,
			StartsAt: at.Add(-5 * time.Minute), Replicas: []string{model.Unmapped},
			Reasons: []model.Reason{model.ReasonUnmappedHost, model.ReasonUnmatchedDefault},
		},
		heartbeat(),
	}
	// heartbeat host-a sorts before unmapped
	v.Alerts[0], v.Alerts[1] = v.Alerts[1], v.Alerts[0]
	v.Sources[0].AlertCount = 2
	return v
}

func verdictBytes(t testing.TB, c goldenCase) []byte {
	t.Helper()
	if c.fixture != "" {
		return read(t, root, "testdata", "fixtures", c.fixture, "expected.json")
	}
	var buf bytes.Buffer
	if err := render.JSON(&buf, c.build()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func write(t testing.TB, b []byte, path ...string) {
	t.Helper()
	p := filepath.Join(path...)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func validate(t testing.TB, s *jsonschema.Schema, doc []byte, what string) {
	t.Helper()
	if err := s.Validate(parse(t, doc)); err != nil {
		t.Errorf("%s does not validate: %v", what, err)
	}
}

// TestVigilGoldens is the conformance test for the Vigil block: every golden's
// verdict is a real verdict (and equals its source), the reference transform
// reproduces block.json and verdict_entry.json byte for byte, the block and the
// entry validate against their schemas, and a Vigil summary assembled from them
// validates against Vigil's own pinned schema. Run with -update to rewrite.
func TestVigilGoldens(t *testing.T) {
	s := loadSchemas(t)
	if len(cases) < 10 {
		t.Fatal("expected at least ten golden cases")
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := filepath.Join(vigilRoot, c.name)
			src := verdictBytes(t, c)
			block, entry, err := vigilmap.FromVerdictJSON(src)
			if err != nil {
				t.Fatal(err)
			}
			blockJSON, err := block.JSON()
			if err != nil {
				t.Fatal(err)
			}
			entryJSON, err := entry.JSON()
			if err != nil {
				t.Fatal(err)
			}
			if *update {
				write(t, src, dir, "verdict.json")
				write(t, blockJSON, dir, "block.json")
				write(t, entryJSON, dir, "verdict_entry.json")
			}
			for name, want := range map[string][]byte{"verdict.json": src, "block.json": blockJSON, "verdict_entry.json": entryJSON} {
				if got := read(t, dir, name); !bytes.Equal(got, want) {
					t.Errorf("%s differs from what the source and the transform produce (run go test ./internal/vigilmap -update)\n got: %s\nwant: %s", name, got, want)
				}
			}

			validate(t, s.verdict, src, "verdict.json (verdict.v0.json)")
			validate(t, s.block, blockJSON, "block.json (vigil-block.v0.json)")
			validate(t, s.vigilVerdict, entryJSON, "verdict_entry.json (Vigil $defs/verdict)")

			// The joint check: the summary Vigil would build validates against
			// Vigil's own schema, with our block in augur{}.
			var blockAny, entryAny any
			if err := json.Unmarshal(blockJSON, &blockAny); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(entryJSON, &entryAny); err != nil {
				t.Fatal(err)
			}
			summary, err := json.Marshal(map[string]any{
				"apiVersion": "vigil.summary/v0", "generated_at": entry.ObservedAt, "overall": entry.Severity,
				"verdicts": []any{entryAny}, "hosts": []any{},
				"sources": []any{map[string]any{"id": "augur", "kind": "augur", "state": "ok", "observed_at": entry.ObservedAt, "last_ok": entry.ObservedAt}},
				"augur":   blockAny,
			})
			if err != nil {
				t.Fatal(err)
			}
			validate(t, s.vigil, summary, "the assembled vigil.summary/v0")
		})
	}
}

// The goldens directory holds exactly the declared cases and the vendor folder.
func TestVigilNoStrayGoldens(t *testing.T) {
	entries, err := os.ReadDir(vigilRoot)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"vendor": true}
	for _, c := range cases {
		want[c.name] = true
	}
	for _, e := range entries {
		if !want[e.Name()] {
			t.Errorf("testdata/vigil/%s is not a declared case", e.Name())
		}
		delete(want, e.Name())
	}
	for name := range want {
		t.Errorf("testdata/vigil/%s is missing (run go test ./internal/vigilmap -update)", name)
	}
}

// The block's closed reason enum is the verdict's, entry for entry, so a code
// added to one and not the other fails here.
func TestVigilBlockReasonEnumEqualsVerdict(t *testing.T) {
	enum := func(file string) []string {
		var doc struct {
			Defs struct {
				Reason struct {
					Enum []string `json:"enum"`
				} `json:"reason"`
			} `json:"$defs"`
		}
		if err := json.Unmarshal(read(t, root, "schema", file), &doc); err != nil {
			t.Fatal(err)
		}
		return doc.Defs.Reason.Enum
	}
	a, b := enum("verdict.v0.json"), enum("vigil-block.v0.json")
	if len(a) == 0 || strings.Join(a, ",") != strings.Join(b, ",") {
		t.Fatalf("block enum %v differs from verdict enum %v", b, a)
	}
}
