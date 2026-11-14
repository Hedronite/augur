package engine_test

import (
	"regexp"
	"testing"
	"time"

	"github.com/Hedronite/augur/internal/engine"
	"github.com/Hedronite/augur/internal/model"
)

var now = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

func eq(v string) model.Matcher { return model.Matcher{Equals: v} }

// testPolicy mirrors the shape of examples/policy.yaml, built in Go so the
// engine tests do not depend on the policy parser.
func testPolicy(replicas []string) model.Policy {
	return model.Policy{
		Default:             model.Yellow,
		HostLabel:           "host",
		ReplicaLabel:        "replica",
		Replicas:            replicas,
		Watchdog:            model.Watchdog{AlertName: "Watchdog", DeadmanWindow: 5 * time.Minute},
		NodeExporterRedHold: 10 * time.Minute,
		FirstClassHosts:     []string{"host-a", "host-b"},
		Rules: []model.Rule{
			{ID: "peer-prom-down", Match: model.Match{"alertname": eq("PeerPrometheusDown")}, Severity: model.Yellow},
			{ID: "node-exporter-down", Match: model.Match{"alertname": eq("NodeExporterDown")}, Severity: model.Yellow,
				Escalate: &model.Escalate{After: 10 * time.Minute, Hosts: model.HostsFirstClass}},
			{ID: "disk", Match: model.Match{"alertname": eq("DiskSpaceCritical")}, Severity: model.Red},
		},
		Holds: []model.Hold{
			{ID: "kube-dark", Match: model.Match{"port": eq("6443")}, Kind: model.HoldExpectedDark},
			{ID: "maint", Match: model.Match{"host": eq("host-e")}, Kind: model.HoldAnnouncedDark, ExpiresAt: now},
		},
		SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
	}
}

func alert(name, host string, startsAgo time.Duration, extra ...string) model.Alert {
	labels := map[string]string{"alertname": name}
	if host != "" {
		labels["host"] = host
	}
	for i := 0; i+1 < len(extra); i += 2 {
		labels[extra[i]] = extra[i+1]
	}
	return model.Alert{
		Name: name, Labels: labels, State: model.StateActive,
		StartsAt: now.Add(-startsAgo), UpdatedAt: now.Add(-time.Minute),
	}
}

func snap(as ...model.Alert) model.Snapshot {
	ok := now
	return model.Snapshot{SourceID: "file", State: model.SourceOK, LastOK: &ok, Alerts: as}
}

func watchdog() model.Alert { return alert("Watchdog", "host-a", 24*time.Hour) }

func find(t *testing.T, v model.Verdict, name string) model.VerdictAlert {
	t.Helper()
	for _, a := range v.Alerts {
		if a.Name == name {
			return a
		}
	}
	t.Fatalf("no alert %q in verdict", name)
	return model.VerdictAlert{}
}

func has(rs []model.Reason, r model.Reason) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}

// The hold is "past" at exactly node_exporter_red_hold.
func TestEscalationEdge(t *testing.T) {
	cases := []struct {
		ago  time.Duration
		want model.Severity
		why  model.Reason
	}{
		{10*time.Minute - time.Nanosecond, model.Yellow, model.ReasonNodeExporterWithinHold},
		{10 * time.Minute, model.Red, model.ReasonNodeExporterSingleView},
		{10*time.Minute + time.Nanosecond, model.Red, model.ReasonNodeExporterSingleView},
	}
	for _, c := range cases {
		v := engine.Evaluate(snap(watchdog(), alert("NodeExporterDown", "host-a", c.ago)), testPolicy(nil), now)
		a := find(t, v, "NodeExporterDown")
		if a.Severity != c.want || !has(a.Reasons, c.why) || v.Overall != c.want {
			t.Errorf("ago %v: severity %s overall %s reasons %v, want %s with %s", c.ago, a.Severity, v.Overall, a.Reasons, c.want, c.why)
		}
	}
}

func TestOnlyFirstClassEscalates(t *testing.T) {
	v := engine.Evaluate(snap(watchdog(), alert("NodeExporterDown", "host-d", time.Hour)), testPolicy(nil), now)
	a := find(t, v, "NodeExporterDown")
	if a.Severity != model.Yellow || v.Overall != model.Yellow {
		t.Fatalf("non-first-class host escalated: %+v", a)
	}
}

// An announced dark holds before expires_at and has expired at expires_at.
func TestAnnouncedDarkExpiryEdge(t *testing.T) {
	p := testPolicy(nil)
	p.Holds[1].ExpiresAt = now.Add(time.Nanosecond)
	v := engine.Evaluate(snap(watchdog(), alert("CustomJob", "host-e", time.Hour)), p, now)
	if a := find(t, v, "CustomJob"); !a.Expected || !has(a.Reasons, model.ReasonHeldAnnouncedDark) || v.Overall != model.Green {
		t.Fatalf("before expiry: %+v overall %s", a, v.Overall)
	}
	p.Holds[1].ExpiresAt = now
	v = engine.Evaluate(snap(watchdog(), alert("CustomJob", "host-e", time.Hour)), p, now)
	if a := find(t, v, "CustomJob"); a.Expected || !has(a.Reasons, model.ReasonAnnouncedDarkExpired) || v.Overall != model.Yellow {
		t.Fatalf("at expiry: %+v overall %s", a, v.Overall)
	}
}

// Unmapped hosts never escalate under first_class, but do under "all".
func TestEscalationHostScope(t *testing.T) {
	p := testPolicy(nil)
	v := engine.Evaluate(snap(watchdog(), alert("NodeExporterDown", "Not A Slug", time.Hour)), p, now)
	if a := find(t, v, "NodeExporterDown"); a.Severity != model.Yellow || a.Host != model.Unmapped || !has(a.Reasons, model.ReasonUnmappedHost) {
		t.Fatalf("first_class: %+v", a)
	}
	p.Rules[1].Escalate.Hosts = model.HostsAll
	v = engine.Evaluate(snap(watchdog(), alert("NodeExporterDown", "Not A Slug", time.Hour)), p, now)
	if a := find(t, v, "NodeExporterDown"); a.Severity != model.Red {
		t.Fatalf("all: %+v", a)
	}
}

// With replicas declared, the table of SPEC section 5.
func TestReplicasRule(t *testing.T) {
	p := testPolicy([]string{"r1", "r2"})
	ne := func(ago time.Duration, replica string) model.Alert {
		return alert("NodeExporterDown", "host-a", ago, "replica", replica)
	}
	peer := func(replica string) model.Alert {
		return alert("PeerPrometheusDown", "host-b", time.Hour, "replica", replica)
	}
	cases := []struct {
		name     string
		alerts   []model.Alert
		sev      model.Severity
		reason   model.Reason
		replicas []string
	}{
		{"both report past hold", []model.Alert{ne(time.Hour, "r1"), ne(30*time.Minute, "r2")}, model.Red, model.ReasonNodeExporterBothViews, []string{"r1", "r2"}},
		{"both report, merged age within hold", []model.Alert{ne(time.Hour, "r1"), ne(5*time.Minute, "r2")}, model.Yellow, model.ReasonNodeExporterWithinHold, []string{"r1", "r2"}},
		{"one report, other live and silent", []model.Alert{ne(time.Hour, "r1")}, model.Yellow, model.ReasonNodeExporterViewsSplit, []string{"r1"}},
		{"one report, other lost", []model.Alert{ne(time.Hour, "r1"), peer("r2")}, model.Red, model.ReasonNodeExporterSingleView, []string{"r1"}},
		{"lost peer, merged age still within hold", []model.Alert{ne(5*time.Minute, "r1"), peer("r2")}, model.Yellow, model.ReasonNodeExporterWithinHold, []string{"r1"}},
		{"the reporter itself is lost", []model.Alert{ne(time.Hour, "r1"), peer("r1")}, model.Yellow, model.ReasonNodeExporterViewsSplit, []string{"r1"}},
		{"unlabeled report cannot be attributed", []model.Alert{alert("NodeExporterDown", "host-a", time.Hour)}, model.Red, model.ReasonNodeExporterSingleView, []string{}},
		{"undeclared replica cannot be attributed", []model.Alert{ne(time.Hour, "r9")}, model.Red, model.ReasonNodeExporterSingleView, []string{"r9"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := engine.Evaluate(snap(append([]model.Alert{watchdog()}, c.alerts...)...), p, now)
			a := find(t, v, "NodeExporterDown")
			if a.Severity != c.sev || !has(a.Reasons, c.reason) {
				t.Fatalf("severity %s reasons %v, want %s with %s", a.Severity, a.Reasons, c.sev, c.reason)
			}
			if len(a.Replicas) != len(c.replicas) {
				t.Fatalf("replicas %v, want %v", a.Replicas, c.replicas)
			}
		})
	}
}

// replicas unset: replica labels are listed but ignored for agreement.
func TestReplicasUnsetIsOneView(t *testing.T) {
	v := engine.Evaluate(snap(watchdog(),
		alert("NodeExporterDown", "host-a", time.Hour, "replica", "r1")), testPolicy(nil), now)
	a := find(t, v, "NodeExporterDown")
	if a.Severity != model.Red || !has(a.Reasons, model.ReasonNodeExporterSingleView) || len(a.Replicas) != 1 {
		t.Fatalf("%+v", a)
	}
}

func TestSourceStateFloorsYellow(t *testing.T) {
	for _, st := range []model.SourceState{model.SourceUnreachable, model.SourceStale} {
		s := snap(watchdog())
		s.State = st
		v := engine.Evaluate(s, testPolicy(nil), now)
		want := model.ReasonSourceUnreachable
		if st == model.SourceStale {
			want = model.ReasonSourceStale
		}
		if v.Overall != model.Yellow || !has(v.Reasons, want) || has(v.Reasons, model.ReasonWatchdogOnly) {
			t.Errorf("%s: overall %s reasons %v", st, v.Overall, v.Reasons)
		}
	}
}

func TestEmptySnapshotIsYellowWatchdogMissing(t *testing.T) {
	v := engine.Evaluate(snap(), testPolicy(nil), now)
	if v.Overall != model.Yellow || !has(v.Reasons, model.ReasonWatchdogMissing) || v.Watchdog.Seen || v.Watchdog.LastSeen != nil {
		t.Fatalf("%+v", v)
	}
	if v.Alerts == nil || v.Reasons == nil || v.Sources == nil {
		t.Fatal("slices must not be nil")
	}
}

// A held alert is excused even when its rule says RED, and shows YELLOW.
func TestHeldAlertNeverReadsRed(t *testing.T) {
	v := engine.Evaluate(snap(watchdog(), alert("DiskSpaceCritical", "host-a", time.Hour, "port", "6443")), testPolicy(nil), now)
	a := find(t, v, "DiskSpaceCritical")
	if !a.Expected || a.Severity == model.Red || v.Overall != model.Green {
		t.Fatalf("%+v overall %s", a, v.Overall)
	}
}

// The engine bounds what it echoes even if the decoder did not.
func TestEngineBoundsOutputStrings(t *testing.T) {
	bad := "BAD\x00\n label"
	a := alert("X", "host-a", time.Minute)
	a.Name = bad
	a.SourceSeverity = &bad
	a.Labels["replica"] = bad
	v := engine.Evaluate(snap(watchdog(), a), testPolicy(nil), now)
	got := find(t, v, model.Unnamed)
	if got.SourceSeverity != nil || len(got.Replicas) != 1 || got.Replicas[0] != model.Unmapped {
		t.Fatalf("%+v", got)
	}
	re := regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	if !re.MatchString(got.Host) {
		t.Fatalf("host %q", got.Host)
	}
}
