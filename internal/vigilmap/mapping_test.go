package vigilmap_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Hedronite/augur/internal/model"
	"github.com/Hedronite/augur/internal/render"
	"github.com/Hedronite/augur/internal/vigilmap"
)

func mapVerdict(t *testing.T, v model.Verdict) (vigilmap.Block, vigilmap.Entry) {
	t.Helper()
	var buf bytes.Buffer
	if err := render.JSON(&buf, v); err != nil {
		t.Fatal(err)
	}
	b, e, err := vigilmap.FromVerdictJSON(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return b, e
}

func TestEntryPassesTheRollupThrough(t *testing.T) {
	v := blindUnreachable()
	_, e := mapVerdict(t, v)
	if e.Source != "augur" || e.State != "ok" || e.Severity != "RED" || e.ObservedAt != "2026-01-15T12:00:00Z" {
		t.Fatalf("%+v", e)
	}
	want := []string{"alertmanager_unreachable", "observability_blind", "watchdog_missing"}
	if len(e.Reasons) != len(want) {
		t.Fatalf("reasons %v", e.Reasons)
	}
	for i := range want {
		if e.Reasons[i] != want[i] {
			t.Fatalf("reasons %v, want %v", e.Reasons, want)
		}
	}
}

// The cap lists 50 raising alerts, RED first, then oldest first, and counts what it left out.
func TestCapOrderAndOmitted(t *testing.T) {
	b, _ := mapVerdict(t, truncated())
	if len(b.Alerts) != vigilmap.MaxAlerts || b.Omitted != 10 {
		t.Fatalf("listed %d, omitted %d", len(b.Alerts), b.Omitted)
	}
	if b.Counts.Total != 61 || b.Counts.Raising.Red != 5 || b.Counts.Raising.Yellow != 55 || b.Counts.Expected != 1 || b.Counts.Suppressed != 0 {
		t.Fatalf("%+v", b.Counts)
	}
	for i := 0; i < 5; i++ {
		if b.Alerts[i].Severity != "RED" {
			t.Fatalf("alert %d is %s, want the five REDs first", i, b.Alerts[i].Severity)
		}
	}
	for i := 6; i < len(b.Alerts); i++ {
		if b.Alerts[i].Severity != "YELLOW" || b.Alerts[i-1].Severity == "YELLOW" && b.Alerts[i].StartsAt < b.Alerts[i-1].StartsAt {
			t.Fatalf("alert %d out of order", i)
		}
	}
}

// Held and suppressed alerts are counted but never listed.
func TestHeldAndSuppressedAreCountedNotListed(t *testing.T) {
	for _, name := range []string{"held-only", "suppressed-only"} {
		var c goldenCase
		for _, x := range cases {
			if x.name == name {
				c = x
			}
		}
		b, _, err := vigilmap.FromVerdictJSON(verdictBytes(t, c))
		if err != nil {
			t.Fatal(err)
		}
		if len(b.Alerts) != 0 || b.Counts.Raising.Red+b.Counts.Raising.Yellow != 0 {
			t.Errorf("%s: %+v", name, b)
		}
		if b.Counts.Expected+b.Counts.Suppressed < 2 && b.Counts.Total < 2 {
			t.Errorf("%s: counts %+v", name, b.Counts)
		}
	}
}

func TestNoStatusOrSourceDetailInTheBlock(t *testing.T) {
	b, _ := mapVerdict(t, staleSource())
	raw, err := b.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"sources", "state", "status", "time_source", "reasons"} {
		if _, ok := m[banned]; ok {
			t.Errorf("the block must not carry %q at the top level", banned)
		}
	}
	if *b.AlertmanagerLastOK != "2026-01-15T12:00:00Z" {
		t.Errorf("alertmanager_last_ok = %v", *b.AlertmanagerLastOK)
	}
}

func TestRefusesUnknownVersionAndOverall(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":     `{`,
		"wrong major":  `{"apiVersion":"augur.verdict/v9","overall":"GREEN"}`,
		"bad overall":  `{"apiVersion":"augur.verdict/v0","overall":"BLUE"}`,
		"old key name": `{"schema":"augur.verdict/v0","overall":"GREEN"}`,
	} {
		if _, _, err := vigilmap.FromVerdictJSON([]byte(doc)); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}
