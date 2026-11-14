package render

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hedronite/augur/internal/model"
)

// fixture50Verdict reproduces the verdict document in
// testdata/fixtures/50-node-exporter-past-hold-single-view/expected.json, so
// the canonical JSON can be pinned to the A0 contract byte for byte.
func fixture50Verdict() model.Verdict {
	generated := mustTime("2026-01-15T12:00:00Z")
	lastSeen := mustTime("2026-01-15T11:58:00Z")
	nodeStart := mustTime("2026-01-15T11:45:00Z")
	watchStart := mustTime("2025-12-01T00:00:00Z")
	rule := "node-exporter-down"
	return model.Verdict{
		APIVersion:   model.VerdictAPIVersion,
		GeneratedAt:  generated,
		TimeSource:   model.TimeFlag,
		Overall:      model.Red,
		PolicySHA256: "b7f1fe1bbea7192242367d18b20f37b7ccd2770678506c4845345277ff6ec048",
		Reasons:      []model.Reason{},
		Watchdog: model.WatchdogState{
			Seen:     true,
			LastSeen: &lastSeen,
		},
		Sources: []model.Source{
			{ID: "file", State: model.SourceOK, LastOK: &generated, AlertCount: 2},
		},
		Alerts: []model.VerdictAlert{
			{
				Name:     "NodeExporterDown",
				Host:     "host-a",
				Severity: model.Red,
				Expected: false,
				Status:   model.StatusActive,
				StartsAt: nodeStart,
				Replicas: []string{},
				RuleID:   &rule,
				Reasons:  []model.Reason{model.ReasonNodeExporterSingleView, model.ReasonRuleMatched},
			},
			{
				Name:     "Watchdog",
				Host:     "host-a",
				Severity: model.Green,
				Expected: true,
				Status:   model.StatusActive,
				StartsAt: watchStart,
				Replicas: []string{},
				RuleID:   nil,
				Reasons:  []model.Reason{model.ReasonHeartbeat},
			},
		},
	}
}

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// goldenPath resolves a golden file under internal/render/testdata.
func goldenPath(name string) string {
	return filepath.Join("testdata", "golden", name)
}

// compareGolden writes the golden when UPDATE_GOLDEN=1, otherwise compares.
func compareGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := goldenPath(name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden %s missing; run UPDATE_GOLDEN=1 go test ./internal/render to seed: %v", name, err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("golden %s mismatch\nwant:\n%s\ngot:\n%s", name, want, got)
	}
}

// TestJSONMatchesFixture50 pins the canonical JSON to the A0 contract:
// the bytes must equal the expected.json fixture, including the trailing
// newline, key order and empty-slice forms.
func TestJSONMatchesFixture50(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("..", "..", "testdata",
		"fixtures", "50-node-exporter-past-hold-single-view", "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := JSON(&buf, fixture50Verdict()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, buf.Bytes()) {
		t.Errorf("canonical JSON does not match fixture 50\nwant:\n%s\ngot:\n%s", want, buf.String())
	}
}

// TestJSONEmptyForms checks the two null/[] corners the fixtures' fixtures
// cover only implicitly: an unseen heartbeat is null, never "", and empty
// slices are [], never null.
func TestJSONEmptyForms(t *testing.T) {
	v := fixture50Verdict()
	v.Reasons = nil
	v.Watchdog = model.WatchdogState{Seen: false, LastSeen: nil}
	v.Sources = nil
	v.Alerts = []model.VerdictAlert{{Reasons: nil, Replicas: nil}}

	var buf bytes.Buffer
	if err := JSON(&buf, v); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		`"last_seen": null`,
		`"reasons": []`,
		`"sources": []`,
		`"replicas": []`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("canonical JSON missing %s\ngot:\n%s", want, out)
		}
	}
}

// TestHumanGolden pins the human rendering. Two verdicts: the fixture-50
// shape, and an empty snapshot (no alerts at all).
func TestHumanGolden(t *testing.T) {
	cases := []struct {
		name string
		v    model.Verdict
	}{
		{"human-fixture50.golden", fixture50Verdict()},
		{"human-empty.golden", model.Verdict{
			APIVersion:   model.VerdictAPIVersion,
			GeneratedAt:  mustTime("2026-01-15T12:00:00Z"),
			TimeSource:   model.TimeWall,
			Overall:      model.Yellow,
			PolicySHA256: "b7f1fe1bbea7192242367d18b20f37b7ccd2770678506c4845345277ff6ec048",
			Reasons:      []model.Reason{model.ReasonWatchdogMissing},
			Watchdog:     model.WatchdogState{Seen: false},
			Sources: []model.Source{
				{ID: "file", State: model.SourceOK, LastOK: nil, AlertCount: 0},
			},
			Alerts: nil,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := Human(&buf, tc.v); err != nil {
				t.Fatal(err)
			}
			compareGolden(t, tc.name, buf.Bytes())
		})
	}
}

// TestErrorsGolden pins the house-style error rendering: every error listed,
// excerpts bounded and control-character-free, line numbers shown when
// known, fixes indented under their location line.
func TestErrorsGolden(t *testing.T) {
	long := strings.Repeat("abcdefgh ", 40) + "\tcontrol\x07chars\nsecond line"
	errs := []model.FieldError{
		{Line: 3, Path: "default", Value: "GREEN", Problem: "default must not be GREEN",
			Fix: "use YELLOW or RED; GREEN is reserved for a verified heartbeat"},
		{Line: 9, Path: "node_exporter_red_hold", Value: long,
			Problem: "not a duration", Fix: "use a duration like 5m, 10m, or 90s"},
		{Line: 0, Path: "schema", Value: "", Problem: "missing", Fix: "add schema: augur.policy/v0"},
	}
	var buf bytes.Buffer
	if err := Errors(&buf, "policy.yaml", errs); err != nil {
		t.Fatal(err)
	}
	compareGolden(t, "errors.golden", buf.Bytes())
}

// TestExcerptBounds is a direct check of the excerpt guard: the raw value
// never reaches the output unbounded.
func TestExcerptBounds(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"a\nb\tc\x07d", "abcd"},
		{"   spaced   out   ", "spaced out"},
		{"", "(empty)"},
		{"\n\t ", "(empty)"},
		{strings.Repeat("x", excerptLimit+10), strings.Repeat("x", excerptLimit) + "…"},
	}
	for _, tc := range cases {
		if got := excerpt(tc.in); got != tc.want {
			t.Errorf("excerpt(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestHumanDeterministic checks byte stability across repeats and writers.
func TestHumanDeterministic(t *testing.T) {
	var a, b bytes.Buffer
	if err := Human(&a, fixture50Verdict()); err != nil {
		t.Fatal(err)
	}
	if err := Human(&b, fixture50Verdict()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("human output is not deterministic")
	}
}
