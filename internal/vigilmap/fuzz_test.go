package vigilmap_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/Hedronite/augur/internal/engine"
	"github.com/Hedronite/augur/internal/model"
	"github.com/Hedronite/augur/internal/render"
	"github.com/Hedronite/augur/internal/vigilmap"
)

func eq(v string) model.Matcher { return model.Matcher{Equals: v} }

func fuzzPolicy(def model.Severity) model.Policy {
	return model.Policy{
		Default: def, HostLabel: "host", ReplicaLabel: "replica",
		Watchdog:            model.Watchdog{AlertName: "Watchdog", DeadmanWindow: 5 * time.Minute},
		NodeExporterRedHold: 10 * time.Minute, FirstClassHosts: []string{"host-a", "host-b"},
		Rules: []model.Rule{
			{ID: "peer", Match: model.Match{"alertname": eq("PeerPrometheusDown")}, Severity: model.Yellow},
			{ID: "disk", Match: model.Match{"alertname": eq("DiskSpaceCritical")}, Severity: model.Red},
			{ID: "ne", Match: model.Match{"alertname": eq("NodeExporterDown")}, Severity: model.Yellow,
				Escalate: &model.Escalate{After: 10 * time.Minute, Hosts: model.HostsFirstClass}},
		},
		Holds:  []model.Hold{{ID: "dark", Match: model.Match{"port": eq("6443")}, Kind: model.HoldExpectedDark}},
		SHA256: digest,
	}
}

// genVerdictJSON builds a real verdict (engine over a random snapshot) with up
// to a few hundred alerts, so the cap is exercised, and renders it.
func genVerdictJSON(t testing.TB, seed int64, junk string) []byte {
	r := rand.New(rand.NewSource(seed))
	names := []string{"NodeExporterDown", "PeerPrometheusDown", "DiskSpaceCritical", "CustomJobFailed", "Watchdog", "9bad", ""}
	hosts := []string{"host-a", "host-b", "host-c", "host-d", "host-e", "-lead", "Host_A", ""}
	states := []model.AlertState{model.StateActive, model.StateActive, model.StateActive, model.StateSilenced, model.StateInhibited, model.StateUnprocessed}
	n := r.Intn(240)
	var as []model.Alert
	for i := 0; i < n; i++ {
		name := names[r.Intn(len(names))]
		if r.Intn(3) == 0 {
			name = fmt.Sprintf("Synthetic%d", r.Intn(150)) // many distinct pairs
		}
		a := model.Alert{
			Name: name, Labels: map[string]string{}, State: states[r.Intn(len(states))],
			StartsAt: at.Add(-time.Duration(r.Intn(600)) * time.Minute), UpdatedAt: at.Add(-time.Minute),
		}
		if name != "" {
			a.Labels["alertname"] = name
		}
		if h := hosts[r.Intn(len(hosts))]; h != "" {
			a.Labels["host"] = h
		}
		if r.Intn(5) == 0 {
			a.Labels["port"] = "6443"
		}
		if junk != "" && r.Intn(4) == 0 {
			a.Name = junk
			a.Labels["host"] = junk
		}
		as = append(as, a)
	}
	state := model.SourceOK
	if r.Intn(8) == 0 {
		state = model.SourceUnreachable
		as = nil
	}
	def := model.Yellow
	if r.Intn(4) == 0 {
		def = model.Red
	}
	v := engine.Evaluate(model.Snapshot{SourceID: "alertmanager", State: state, LastOK: &at, Alerts: as}, fuzzPolicy(def), at)
	v.TimeSource = model.TimeWall
	var buf bytes.Buffer
	if err := render.JSON(&buf, v); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func checkMapping(t testing.TB, s schemas, seed int64, junk string) {
	src := genVerdictJSON(t, seed, junk)
	block, entry, err := vigilmap.FromVerdictJSON(src)
	if err != nil {
		t.Fatalf("seed %d: %v", seed, err)
	}
	blockJSON, err := block.JSON()
	if err != nil {
		t.Fatal(err)
	}
	entryJSON, err := entry.JSON()
	if err != nil {
		t.Fatal(err)
	}

	// Always valid, and never over the cap.
	if err := s.block.Validate(parse(t, blockJSON)); err != nil {
		t.Fatalf("seed %d: block does not validate: %v", seed, err)
	}
	if err := s.vigilVerdict.Validate(parse(t, entryJSON)); err != nil {
		t.Fatalf("seed %d: entry does not validate: %v", seed, err)
	}
	if len(block.Alerts) > vigilmap.MaxAlerts {
		t.Fatalf("seed %d: %d alerts listed", seed, len(block.Alerts))
	}

	// The counts partition total, and omitted accounts for what is not listed.
	c := block.Counts
	if c.Total != c.Raising.Red+c.Raising.Yellow+c.Expected+c.Suppressed {
		t.Fatalf("seed %d: counts do not partition total: %+v", seed, c)
	}
	if block.Omitted != c.Raising.Red+c.Raising.Yellow-len(block.Alerts) {
		t.Fatalf("seed %d: omitted %d, counts %+v, listed %d", seed, block.Omitted, c, len(block.Alerts))
	}

	// RED first: a cap can never list a YELLOW while a RED is left out.
	seenYellow := false
	listedRed := 0
	for _, a := range block.Alerts {
		if a.Severity == "RED" {
			listedRed++
			if seenYellow {
				t.Fatalf("seed %d: a RED after a YELLOW", seed)
			}
		} else {
			seenYellow = true
		}
	}
	if seenYellow && listedRed != c.Raising.Red {
		t.Fatalf("seed %d: a YELLOW is listed while %d RED are not", seed, c.Raising.Red-listedRed)
	}
	if c.Raising.Red > 0 && (len(block.Alerts) == 0 || block.Alerts[0].Severity != "RED") {
		t.Fatalf("seed %d: RED exists but the list does not start with one", seed)
	}

	// Byte-stable.
	b2, _, _ := vigilmap.FromVerdictJSON(src)
	again, _ := b2.JSON()
	if !bytes.Equal(blockJSON, again) {
		t.Fatalf("seed %d: not byte-stable", seed)
	}
}

func TestVigilMapProperties(t *testing.T) {
	s := loadSchemas(t)
	for seed := int64(0); seed < 400; seed++ {
		checkMapping(t, s, seed, "")
	}
	for seed := int64(0); seed < 100; seed++ {
		checkMapping(t, s, seed, "bad\x00\n\"\\ \u202e value")
	}
}

// FuzzVigilMap drives the same properties from fuzzer-chosen seeds.
func FuzzVigilMap(f *testing.F) {
	f.Add(int64(1), "")
	f.Add(int64(9), "x")
	f.Add(int64(77), "bad\x00\n value")
	f.Add(int64(123456), "\u202e")
	f.Fuzz(func(t *testing.T, seed int64, junk string) {
		checkMapping(t, loadSchemas(t), seed, junk)
	})
}
