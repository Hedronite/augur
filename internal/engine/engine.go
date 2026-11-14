// Package engine classifies a snapshot against a policy. It is pure: no I/O,
// no goroutines and no clock; "now" is an argument. The same snapshot, policy
// and now always give the same verdict, whatever the order of the alerts.
package engine

import (
	"sort"
	"strings"
	"time"

	"github.com/Hedronite/augur/internal/model"
)

// Alert names the engine knows by label value (the real rule set's names).
const (
	peerDown   = "PeerPrometheusDown"
	peerAbsent = "PeerPrometheusAbsent"
)

// Evaluate classifies snap against pol as of now. The returned Verdict has
// TimeSource unset (the caller knows where now came from) and every slice
// sorted and non-nil.
func Evaluate(snap model.Snapshot, pol model.Policy, now time.Time) model.Verdict {
	now = now.UTC()
	e := &evaluator{pol: pol, now: now}

	members := make([]member, 0, len(snap.Alerts))
	for _, a := range snap.Alerts {
		members = append(members, e.resolve(a))
	}

	lost := lostReplicas(members)

	groups := make(map[groupKey][]member)
	for _, m := range members {
		k := groupKey{name: m.alert.Name, host: m.host, mapped: m.hostMapped, heartbeat: m.heartbeat}
		groups[k] = append(groups[k], m)
	}

	v := model.Verdict{
		Schema:       model.VerdictSchema,
		GeneratedAt:  now,
		Overall:      model.Green,
		PolicySHA256: pol.SHA256,
		Reasons:      []model.Reason{},
		Sources:      []model.Source{},
		Alerts:       make([]model.VerdictAlert, 0, len(groups)),
	}

	raising := model.Green
	for k, ms := range groups {
		var va model.VerdictAlert
		if k.heartbeat {
			va = e.heartbeatAlert(ms)
			v.Watchdog.Seen = true
			for _, m := range ms {
				t := m.alert.UpdatedAt.UTC()
				if v.Watchdog.LastSeen == nil || t.After(*v.Watchdog.LastSeen) {
					v.Watchdog.LastSeen = &t
				}
			}
		} else {
			va = e.classify(ms, lost)
		}
		if !va.Expected && va.Status != model.StatusSuppressed {
			raising = model.Worse(raising, va.Severity)
		}
		v.Alerts = append(v.Alerts, va)
	}
	sortAlerts(v.Alerts)

	srcOK := snap.State == model.SourceOK
	var rollup []model.Reason
	if !v.Watchdog.Seen {
		rollup = append(rollup, model.ReasonWatchdogMissing)
	}
	switch snap.State {
	case model.SourceOK:
	case model.SourceStale:
		rollup = append(rollup, model.ReasonAlertmanagerStale)
	default: // unreachable, and anything unknown fails closed
		rollup = append(rollup, model.ReasonAlertmanagerUnreachable)
	}

	v.Overall = raising
	if !v.Watchdog.Seen || !srcOK {
		v.Overall = model.Worse(v.Overall, model.Yellow)
	}
	if v.Watchdog.Seen && srcOK && v.Overall == model.Green {
		rollup = append(rollup, model.ReasonWatchdogOnly)
	}
	v.Reasons = sortedReasons(rollup)

	var lastOK *time.Time
	if snap.LastOK != nil {
		t := snap.LastOK.UTC()
		lastOK = &t
	}
	src := snap.State
	if src == "" {
		src = model.SourceUnreachable
	}
	v.Sources = append(v.Sources, model.Source{
		ID:         snap.SourceID,
		State:      src,
		LastOK:     lastOK,
		AlertCount: len(snap.Alerts),
	})
	return v
}

type evaluator struct {
	pol model.Policy
	now time.Time
}

// groupKey merges alerts that share a name and host (the replicas rule's "one
// alert seen by several views"). A literal "unmapped" label value and a value
// that failed the slug bound both report host "unmapped", so mapped is part of
// the key to keep the two apart.
type groupKey struct {
	name      string
	host      string
	mapped    bool
	heartbeat bool
}

// member is one raw alert with its host and replica resolved.
type member struct {
	alert      model.Alert
	labels     map[string]string // effective labels used for matching
	host       string
	hostMapped bool
	replica    string
	hasReplica bool
	heartbeat  bool
}

func (e *evaluator) resolve(a model.Alert) member {
	// The decoder already bounds these; the engine enforces the same bounds so
	// that no unbounded string can reach the output whoever built the snapshot.
	if !model.NamePattern.MatchString(a.Name) {
		a.Name = model.Unnamed
	}
	if a.SourceSeverity != nil && !model.SeverityLabelPattern.MatchString(*a.SourceSeverity) {
		a.SourceSeverity = nil
	}
	m := member{alert: a, labels: a.Labels}
	if e.pol.Watchdog.AlertName != "" && a.Labels["alertname"] == e.pol.Watchdog.AlertName {
		m.heartbeat = true
	}

	hostVal, ok := a.Labels[e.pol.HostLabel]
	if !ok {
		// Fall back to instance, and expose it under the host label so that
		// matchers on the host label see the same value the verdict reports.
		if inst, has := a.Labels["instance"]; has {
			hostVal, ok = inst, true
			eff := make(map[string]string, len(a.Labels)+1)
			for k, v := range a.Labels {
				eff[k] = v
			}
			eff[e.pol.HostLabel] = inst
			m.labels = eff
		}
	}
	if ok {
		m.host, m.hostMapped = model.ResolveSlug(hostVal)
	} else {
		m.host = model.Unmapped
	}

	if r, has := a.Labels[e.pol.ReplicaLabel]; has {
		m.replica, _ = model.ResolveSlug(r)
		m.hasReplica = true
	}
	return m
}

// lostReplicas returns the replicas named by an active peer-down or
// peer-absent alert. A suppressed alert does not count: the peer is only lost
// while the alert is really firing.
func lostReplicas(ms []member) map[string]bool {
	lost := make(map[string]bool)
	for _, m := range ms {
		if !m.hasReplica || m.replica == model.Unmapped || suppressed(m.alert.State) {
			continue
		}
		switch m.alert.Labels["alertname"] {
		case peerDown, peerAbsent:
			lost[m.replica] = true
		}
	}
	return lost
}

func suppressed(s model.AlertState) bool {
	return s == model.StateSilenced || s == model.StateInhibited
}

func (e *evaluator) heartbeatAlert(ms []member) model.VerdictAlert {
	va := baseAlert(ms)
	va.Severity = model.Green
	va.Expected = true
	reasons := []model.Reason{model.ReasonHeartbeat}
	reasons = append(reasons, suppressionReasons(ms)...)
	if !ms[0].hostMapped {
		reasons = append(reasons, model.ReasonUnmappedHost)
	}
	va.Reasons = sortedReasons(reasons)
	return va
}

// baseAlert fills the fields that do not depend on classification.
func baseAlert(ms []member) model.VerdictAlert {
	va := model.VerdictAlert{
		Name:     ms[0].alert.Name,
		Host:     ms[0].host,
		Status:   model.StatusActive,
		Replicas: []string{},
		Reasons:  []model.Reason{},
	}

	seen := make(map[string]bool)
	allSuppressed := true
	for i, m := range ms {
		t := m.alert.StartsAt.UTC()
		if i == 0 || t.After(va.StartsAt) {
			va.StartsAt = t
		}
		if m.hasReplica && !seen[m.replica] {
			seen[m.replica] = true
			va.Replicas = append(va.Replicas, m.replica)
		}
		if !suppressed(m.alert.State) {
			allSuppressed = false
		}
		if s := m.alert.SourceSeverity; s != nil && (va.SourceSeverity == nil || *s < *va.SourceSeverity) {
			c := *s
			va.SourceSeverity = &c
		}
	}
	sort.Strings(va.Replicas)
	if allSuppressed {
		va.Status = model.StatusSuppressed
	}
	return va
}

// suppressionReasons names why a fully suppressed group is suppressed.
func suppressionReasons(ms []member) []model.Reason {
	for _, m := range ms {
		if !suppressed(m.alert.State) {
			return nil
		}
	}
	var out []model.Reason
	var sil, inh bool
	for _, m := range ms {
		switch m.alert.State {
		case model.StateSilenced:
			sil = true
		case model.StateInhibited:
			inh = true
		}
	}
	if sil {
		out = append(out, model.ReasonSilenced)
	}
	if inh {
		out = append(out, model.ReasonInhibited)
	}
	return out
}

// classify applies the policy to one merged (name, host) alert.
func (e *evaluator) classify(ms []member, lost map[string]bool) model.VerdictAlert {
	va := baseAlert(ms)
	var reasons []model.Reason

	if !ms[0].hostMapped {
		reasons = append(reasons, model.ReasonUnmappedHost)
	}

	age := e.now.Sub(va.StartsAt)
	if age < 0 {
		age = 0
		reasons = append(reasons, model.ReasonAlertClockSkew)
	}

	// Holds and suppression are decided before escalation.
	held, heldReasons, expired := e.holds(ms)
	va.Expected = held
	if held {
		reasons = append(reasons, heldReasons...)
	} else if expired {
		reasons = append(reasons, model.ReasonAnnouncedDarkExpired)
	}
	isSuppressed := va.Status == model.StatusSuppressed
	reasons = append(reasons, suppressionReasons(ms)...)

	// Every matching rule applies; the worst final severity wins, and the
	// earliest rule wins a tie.
	sev := model.Severity("")
	var ruleID *string
	matched := false
	for i := range e.pol.Rules {
		r := &e.pol.Rules[i]
		if !anyMatch(ms, r.Match) {
			continue
		}
		matched = true
		final := r.Severity
		if r.Escalate != nil && !held && !isSuppressed && e.escalationApplies(r.Escalate, ms[0]) {
			var er []model.Reason
			final, er = e.escalate(final, r.Escalate, age, va, lost)
			reasons = append(reasons, er...)
		}
		if sev == "" || final.Rank() > sev.Rank() {
			sev = final
			id := r.ID
			ruleID = &id
		}
	}
	if matched {
		reasons = append(reasons, model.ReasonRuleMatched)
	} else {
		sev = e.pol.Default
		reasons = append(reasons, model.ReasonUnmatchedDefault)
	}

	// An excused alert never reads as RED: holds cap its severity at YELLOW.
	// It stays out of overall either way.
	if va.Expected && sev == model.Red {
		sev = model.Yellow
	}
	va.Severity = sev
	va.RuleID = ruleID
	va.Reasons = sortedReasons(reasons)
	return va
}

// holds reports whether every member is excused by an active hold, the reasons
// for it, and whether an expired announced dark matched.
func (e *evaluator) holds(ms []member) (held bool, reasons []model.Reason, expired bool) {
	held = true
	for _, m := range ms {
		excused := false
		for i := range e.pol.Holds {
			h := &e.pol.Holds[i]
			if !h.Match.Matches(m.labels) {
				continue
			}
			if h.Kind == model.HoldAnnouncedDark && !e.now.Before(h.ExpiresAt) {
				expired = true
				continue
			}
			excused = true
			switch h.Kind {
			case model.HoldExpectedDark:
				reasons = append(reasons, model.ReasonHeldExpectedDark)
			case model.HoldKnown:
				reasons = append(reasons, model.ReasonHeldKnown)
			case model.HoldAnnouncedDark:
				reasons = append(reasons, model.ReasonHeldAnnouncedDark)
			}
		}
		if !excused {
			held = false
		}
	}
	if !held {
		reasons = nil
	}
	return held, reasons, expired
}

func anyMatch(ms []member, match model.Match) bool {
	for _, m := range ms {
		if match.Matches(m.labels) {
			return true
		}
	}
	return false
}

func (e *evaluator) escalationApplies(esc *model.Escalate, m member) bool {
	switch esc.Hosts {
	case model.HostsAll:
		return true
	case model.HostsFirstClass:
		if !m.hostMapped {
			return false
		}
		for _, h := range e.pol.FirstClassHosts {
			if h == m.host {
				return true
			}
		}
	}
	return false
}

// escalate decides what an escalating rule does to an alert of the given age.
// It implements the replicas rule (SPEC section 5). Age at or past After is
// "past the hold".
func (e *evaluator) escalate(base model.Severity, esc *model.Escalate, age time.Duration, va model.VerdictAlert, lost map[string]bool) (model.Severity, []model.Reason) {
	if age < esc.After {
		return base, []model.Reason{model.ReasonNodeExporterWithinHold}
	}
	declared := e.pol.Replicas
	if len(declared) == 0 {
		return model.Red, []model.Reason{model.ReasonNodeExporterSingleView}
	}

	reporting := make(map[string]bool, len(va.Replicas))
	for _, r := range va.Replicas {
		reporting[r] = true
	}
	var attributed, silentLive int
	for _, d := range declared {
		if reporting[d] {
			attributed++
		} else if !lost[d] {
			silentLive++
		}
	}
	switch {
	case attributed == 0:
		// The report cannot be attributed to any declared view. Fail closed.
		return model.Red, []model.Reason{model.ReasonNodeExporterSingleView}
	case silentLive > 0:
		return base, []model.Reason{model.ReasonNodeExporterViewsSplit}
	case attributed == len(declared):
		return model.Red, []model.Reason{model.ReasonNodeExporterBothViews}
	default:
		// Every silent declared replica is lost.
		return model.Red, []model.Reason{model.ReasonNodeExporterSingleView}
	}
}

func sortAlerts(as []model.VerdictAlert) {
	sort.Slice(as, func(i, j int) bool {
		a, b := as[i], as[j]
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if !a.StartsAt.Equal(b.StartsAt) {
			return a.StartsAt.Before(b.StartsAt)
		}
		// Same host, name and start: the group keys differ in heartbeat or
		// in mapped, which the reasons always show, so this order is total.
		if isHeartbeat(a) != isHeartbeat(b) {
			return isHeartbeat(a)
		}
		return reasonKey(a) < reasonKey(b)
	})
}

func reasonKey(a model.VerdictAlert) string {
	var b strings.Builder
	for _, r := range a.Reasons {
		b.WriteString(string(r))
		b.WriteByte(',')
	}
	return b.String()
}

func isHeartbeat(a model.VerdictAlert) bool {
	for _, r := range a.Reasons {
		if r == model.ReasonHeartbeat {
			return true
		}
	}
	return false
}

// sortedReasons returns the distinct reasons in ascending order, never nil.
func sortedReasons(rs []model.Reason) []model.Reason {
	out := make([]model.Reason, 0, len(rs))
	seen := make(map[model.Reason]bool, len(rs))
	for _, r := range rs {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
