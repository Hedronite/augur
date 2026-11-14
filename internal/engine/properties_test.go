package engine_test

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/Hedronite/augur/internal/engine"
	"github.com/Hedronite/augur/internal/model"
)

// The properties the engine promises, checked on generated snapshots and by
// FuzzEvaluate:
//
//  1. deterministic;
//  2. a permutation of the alerts gives an identical verdict;
//  3. the Watchdog and held alerts never raise overall, so overall is exactly
//     the worst severity of the alerts that are neither expected nor
//     suppressed, floored at YELLOW without a heartbeat or a healthy source;
//  4. an expected alert is never RED;
//  5. every string in the output is an enum value or matches its bound.

var (
	poolNames    = []string{"Watchdog", "NodeExporterDown", "PeerPrometheusDown", "PeerPrometheusAbsent", "DiskSpaceCritical", "SSHFailure", "CustomJobFailed", "", "9bad", "has space"}
	poolHosts    = []string{"host-a", "host-b", "host-c", "host-d", "host-e", "", "Host_A", "a/very/long/host/value/that/is/not/a/slug/at/all"}
	poolReplicas = []string{"", "r1", "r2", "r3", "R1", "bad value"}
	poolPorts    = []string{"", "6443", "18080", "22"}
	poolStates   = []model.AlertState{model.StateActive, model.StateActive, model.StateSilenced, model.StateInhibited, model.StateUnprocessed}
	poolSev      = []string{"", "critical", "warning", "CRIT", "ok_1"}
	poolOffsets  = []time.Duration{-time.Hour, 0, time.Second, 9*time.Minute + 59*time.Second, 10 * time.Minute, 11 * time.Minute, time.Hour, 72 * time.Hour}
)

func pick[T any](r *rand.Rand, s []T) T { return s[r.Intn(len(s))] }

func genSnapshot(r *rand.Rand, junk string) model.Snapshot {
	n := r.Intn(9)
	as := make([]model.Alert, 0, n)
	for i := 0; i < n; i++ {
		name := pick(r, poolNames)
		a := model.Alert{
			Name:      name,
			Labels:    map[string]string{},
			State:     pick(r, poolStates),
			StartsAt:  now.Add(-pick(r, poolOffsets)),
			UpdatedAt: now.Add(-time.Duration(r.Intn(600)) * time.Second),
		}
		if name != "" {
			a.Labels["alertname"] = name
		}
		if h := pick(r, poolHosts); h != "" {
			a.Labels["host"] = h
		} else if r.Intn(2) == 0 {
			a.Labels["instance"] = pick(r, poolHosts)
		}
		if rep := pick(r, poolReplicas); rep != "" {
			a.Labels["replica"] = rep
		}
		if p := pick(r, poolPorts); p != "" {
			a.Labels["port"] = p
		}
		if s := pick(r, poolSev); s != "" {
			s := s
			a.SourceSeverity = &s
		}
		if junk != "" && r.Intn(3) == 0 {
			switch r.Intn(4) {
			case 0:
				a.Name = junk
			case 1:
				a.Labels["host"] = junk
			case 2:
				a.Labels["replica"] = junk
			default:
				a.SourceSeverity = &junk
			}
		}
		as = append(as, a)
	}
	s := snap(as...)
	if r.Intn(8) == 0 {
		s.State = model.SourceUnreachable
	} else if r.Intn(8) == 0 {
		s.State = model.SourceStale
	}
	return s
}

func genPolicy(r *rand.Rand) model.Policy {
	var reps []string
	switch r.Intn(3) {
	case 1:
		reps = []string{"r1", "r2"}
	case 2:
		reps = []string{"r1", "r2", "r3"}
	}
	p := testPolicy(reps)
	if r.Intn(4) == 0 {
		p.Default = model.Red
	}
	if r.Intn(4) == 0 {
		p.Rules[1].Escalate.Hosts = model.HostsAll
	}
	return p
}

func shuffled(r *rand.Rand, s model.Snapshot) model.Snapshot {
	c := s
	c.Alerts = append([]model.Alert(nil), s.Alerts...)
	r.Shuffle(len(c.Alerts), func(i, j int) { c.Alerts[i], c.Alerts[j] = c.Alerts[j], c.Alerts[i] })
	return c
}

func checkProperties(t *testing.T, seed int64, junk string) {
	t.Helper()
	r := rand.New(rand.NewSource(seed))
	s := genSnapshot(r, junk)
	p := genPolicy(r)

	v := engine.Evaluate(s, p, now)

	// 1. deterministic
	if v2 := engine.Evaluate(s, p, now); !reflect.DeepEqual(v, v2) {
		t.Fatalf("seed %d: not deterministic", seed)
	}
	// 2. permutation
	for i := 0; i < 3; i++ {
		if vp := engine.Evaluate(shuffled(r, s), p, now); !reflect.DeepEqual(v, vp) {
			t.Fatalf("seed %d: a permutation changed the verdict\n%+v\n%+v", seed, v, vp)
		}
	}

	// 3. overall is exactly the worst non-excused, non-suppressed severity.
	worst := model.Green
	for _, a := range v.Alerts {
		if !a.Expected && a.Status != model.StatusSuppressed {
			worst = model.Worse(worst, a.Severity)
		}
	}
	if !v.Watchdog.Seen || s.State != model.SourceOK {
		worst = model.Worse(worst, model.Yellow)
	}
	if v.Overall != worst {
		t.Fatalf("seed %d: overall %s, want %s", seed, v.Overall, worst)
	}
	for _, a := range v.Alerts {
		if has(a.Reasons, model.ReasonHeartbeat) && (!a.Expected || a.Severity != model.Green) {
			t.Fatalf("seed %d: heartbeat alert raised: %+v", seed, a)
		}
		// 4. expected is never RED
		if a.Expected && a.Severity == model.Red {
			t.Fatalf("seed %d: expected alert is RED: %+v", seed, a)
		}
	}

	checkBounds(t, seed, v)
}

func checkBounds(t *testing.T, seed int64, v model.Verdict) {
	t.Helper()
	enum := map[model.Reason]bool{}
	for _, r := range model.AllReasons() {
		enum[r] = true
	}
	reasons := func(rs []model.Reason, where string) {
		for i, r := range rs {
			if !enum[r] {
				t.Fatalf("seed %d: %s reason %q is not in the enum", seed, where, r)
			}
			if i > 0 && rs[i-1] >= r {
				t.Fatalf("seed %d: %s reasons not sorted and distinct: %v", seed, where, rs)
			}
		}
	}
	reasons(v.Reasons, "rollup")
	if v.Schema != model.VerdictSchema || v.TimeSource != "" {
		t.Fatalf("seed %d: schema %q time source %q", seed, v.Schema, v.TimeSource)
	}
	if v.Overall.Rank() > model.Red.Rank() {
		t.Fatalf("seed %d: overall %q", seed, v.Overall)
	}
	for i, a := range v.Alerts {
		where := fmt.Sprintf("alert %d", i)
		if !model.NamePattern.MatchString(a.Name) {
			t.Fatalf("seed %d: %s name %q", seed, where, a.Name)
		}
		if !model.SlugPattern.MatchString(a.Host) {
			t.Fatalf("seed %d: %s host %q", seed, where, a.Host)
		}
		if a.SourceSeverity != nil && !model.SeverityLabelPattern.MatchString(*a.SourceSeverity) {
			t.Fatalf("seed %d: %s source_severity %q", seed, where, *a.SourceSeverity)
		}
		for _, rp := range a.Replicas {
			if !model.SlugPattern.MatchString(rp) {
				t.Fatalf("seed %d: %s replica %q", seed, where, rp)
			}
		}
		if a.RuleID != nil && !model.IDPattern.MatchString(*a.RuleID) {
			t.Fatalf("seed %d: %s rule_id %q", seed, where, *a.RuleID)
		}
		if a.Severity.Rank() > model.Red.Rank() || (a.Status != model.StatusActive && a.Status != model.StatusSuppressed) {
			t.Fatalf("seed %d: %s severity %q status %q", seed, where, a.Severity, a.Status)
		}
		if a.Replicas == nil || a.Reasons == nil {
			t.Fatalf("seed %d: %s nil slice", seed, where)
		}
		reasons(a.Reasons, where)
	}
	for i := 1; i < len(v.Alerts); i++ {
		a, b := v.Alerts[i-1], v.Alerts[i]
		if a.Host > b.Host || (a.Host == b.Host && a.Name > b.Name) {
			t.Fatalf("seed %d: alerts out of order: %s/%s then %s/%s", seed, a.Host, a.Name, b.Host, b.Name)
		}
	}
}

func TestProperties(t *testing.T) {
	for seed := int64(0); seed < 3000; seed++ {
		checkProperties(t, seed, "")
	}
	for seed := int64(0); seed < 500; seed++ {
		checkProperties(t, seed, "bad\x00\n\"\\ value \u202e")
	}
}

// FuzzEvaluate drives the same properties from fuzzer-chosen seeds and junk.
func FuzzEvaluate(f *testing.F) {
	f.Add(int64(1), "")
	f.Add(int64(7), "x")
	f.Add(int64(42), "bad\x00\n value")
	f.Add(int64(1234567), "\u202e\u0000")
	f.Fuzz(func(t *testing.T, seed int64, junk string) {
		checkProperties(t, seed, junk)
	})
}
