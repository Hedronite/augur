package engine_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Hedronite/augur/internal/engine"
	"github.com/Hedronite/augur/internal/model"
)

// Every outcome of the replicas rule, for NodeExporterDown and for any other
// escalating alert: the same severity, and codes from the matching family only.
func TestEscalateReasonFamilies(t *testing.T) {
	cases := []struct {
		name     string
		replicas []string
		ago      time.Duration
		from     []string // replica labels reporting the alert; "" is unlabeled
		want     model.Severity
		node     model.Reason
		generic  model.Reason
	}{
		{"within the hold", nil, time.Minute, []string{""}, model.Yellow,
			model.ReasonNodeExporterWithinHold, model.ReasonEscalateWithinHold},
		{"single view", nil, time.Hour, []string{""}, model.Red,
			model.ReasonNodeExporterSingleView, model.ReasonEscalateSingleView},
		{"unattributed", []string{"r1", "r2"}, time.Hour, []string{""}, model.Red,
			model.ReasonNodeExporterSingleView, model.ReasonEscalateSingleView},
		{"both views", []string{"r1", "r2"}, time.Hour, []string{"r1", "r2"}, model.Red,
			model.ReasonNodeExporterBothViews, model.ReasonEscalateBothViews},
		{"views split", []string{"r1", "r2"}, time.Hour, []string{"r1"}, model.Yellow,
			model.ReasonNodeExporterViewsSplit, model.ReasonEscalateViewsSplit},
	}
	for _, c := range cases {
		for _, name := range []string{"NodeExporterDown", "CertExpiring"} {
			t.Run(name+"/"+c.name, func(t *testing.T) {
				pol := testPolicy(c.replicas)
				pol.Rules = []model.Rule{{ID: "r", Match: model.Match{"alertname": eq(name)}, Severity: model.Yellow,
					Escalate: &model.Escalate{After: 10 * time.Minute, Hosts: model.HostsFirstClass}}}
				as := []model.Alert{watchdog()}
				for _, replica := range c.from {
					if replica == "" {
						as = append(as, alert(name, "host-a", c.ago))
					} else {
						as = append(as, alert(name, "host-a", c.ago, "replica", replica))
					}
				}
				a := find(t, engine.Evaluate(snap(as...), pol, now), name)
				want, other := c.node, "escalate_"
				if name != "NodeExporterDown" {
					want, other = c.generic, "node_exporter_"
				}
				if a.Severity != c.want || !has(a.Reasons, want) {
					t.Fatalf("severity %s reasons %v, want %s with %s", a.Severity, a.Reasons, c.want, want)
				}
				for _, r := range a.Reasons {
					if strings.HasPrefix(string(r), other) {
						t.Errorf("%s emitted %q", name, r)
					}
				}
			})
		}
	}
}

// The header fields the engine owns.
func TestObservedAndDeclaration(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	pol := testPolicy(nil)
	if v := engine.Evaluate(snap(watchdog()), pol, now); !v.Observed || v.Declaration != nil {
		t.Fatalf("a read source, undeclared: %+v", v)
	}
	// An empty set that was read is still an observation.
	if v := engine.Evaluate(snap(), pol, now); !v.Observed || v.Overall == model.Green {
		t.Fatalf("empty: %+v", v)
	}
	pol.Declaration = &digest
	for state, observed := range map[model.SourceState]bool{
		model.SourceStale: true, model.SourceUnreachable: false, "": false, "other": false,
	} {
		s := snap(watchdog())
		s.State = state
		v := engine.Evaluate(s, pol, now)
		if v.Observed != observed || v.Declaration == nil || *v.Declaration != digest {
			t.Errorf("state %q: observed %v declaration %v", state, v.Observed, v.Declaration)
		}
		if !v.Observed && v.Overall == model.Green {
			t.Errorf("state %q: an unobserved verdict is GREEN", state)
		}
	}
}

// An over-cap poll is never observed and never GREEN, whatever state or alerts
// the snapshot claims.
func TestOverCapSnapshot(t *testing.T) {
	for _, state := range []model.SourceState{model.SourceStale, model.SourceOK} {
		s := snap(watchdog())
		s.State, s.OverCap = state, true
		v := engine.Evaluate(s, testPolicy(nil), now)
		if v.Observed || v.Overall == model.Green || !has(v.Reasons, model.ReasonAlertsOverCap) ||
			has(v.Reasons, model.ReasonAlertmanagerUnreachable) || has(v.Reasons, model.ReasonAlertmanagerStale) ||
			has(v.Reasons, model.ReasonWatchdogOnly) {
			t.Errorf("state %q: observed %v overall %s reasons %v", state, v.Observed, v.Overall, v.Reasons)
		}
	}
}
