// Package model holds the types shared by the decoder, the policy parser, the
// engine and the renderers. It has no behaviour beyond small helpers: a value
// of these types is plain data, and the engine is the only place that decides
// what an alert means.
package model

import (
	"regexp"
	"sort"
	"time"
)

// Severity is the shared verdict vocabulary.
type Severity string

// The three verdict severities. GREEN requires a Watchdog heartbeat.
const (
	Green  Severity = "GREEN"
	Yellow Severity = "YELLOW"
	Red    Severity = "RED"
)

// Rank orders severities: GREEN < YELLOW < RED. An unknown value ranks above
// RED so that a bug fails closed rather than quiet.
func (s Severity) Rank() int {
	switch s {
	case Green:
		return 0
	case Yellow:
		return 1
	case Red:
		return 2
	default:
		return 3
	}
}

// Worse returns the more severe of a and b.
func Worse(a, b Severity) Severity {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}

// Reason is one code from the closed reason enum. The set must equal the
// enum in schema/verdict.v0.json; a test in this package asserts that.
type Reason string

// Top-level (rollup) reasons: heartbeat and source state.
const (
	ReasonWatchdogOnly             Reason = "watchdog_only"
	ReasonWatchdogMissing          Reason = "watchdog_missing"
	ReasonObservabilityBlind       Reason = "observability_blind"
	ReasonAlertmanagerUnreachable  Reason = "alertmanager_unreachable"
	ReasonAlertmanagerStale        Reason = "alertmanager_stale"
	ReasonEvaluationClockBackwards Reason = "evaluation_clock_backwards"
)

// Per-alert reasons.
const (
	ReasonHeartbeat              Reason = "heartbeat"
	ReasonRuleMatched            Reason = "rule_matched"
	ReasonUnmatchedDefault       Reason = "unmatched_default"
	ReasonHeldExpectedDark       Reason = "held_expected_dark"
	ReasonHeldKnown              Reason = "held_known"
	ReasonHeldAnnouncedDark      Reason = "held_announced_dark"
	ReasonAnnouncedDarkExpired   Reason = "announced_dark_expired"
	ReasonSilenced               Reason = "silenced"
	ReasonInhibited              Reason = "inhibited"
	ReasonNodeExporterWithinHold Reason = "node_exporter_within_hold"
	ReasonNodeExporterSingleView Reason = "node_exporter_down_single_view"
	ReasonNodeExporterBothViews  Reason = "node_exporter_down_both_views"
	ReasonNodeExporterViewsSplit Reason = "node_exporter_views_split"
	ReasonAlertClockSkew         Reason = "alert_clock_skew"
	ReasonUnmappedHost           Reason = "unmapped_host"
)

// AllReasons returns every reason code, sorted. It is the Go side of the
// closed enum in verdict.v0.json.
func AllReasons() []Reason {
	all := []Reason{
		ReasonWatchdogOnly, ReasonWatchdogMissing, ReasonObservabilityBlind,
		ReasonAlertmanagerUnreachable, ReasonAlertmanagerStale,
		ReasonHeartbeat, ReasonRuleMatched, ReasonUnmatchedDefault,
		ReasonHeldExpectedDark, ReasonHeldKnown, ReasonHeldAnnouncedDark,
		ReasonAnnouncedDarkExpired, ReasonSilenced, ReasonInhibited,
		ReasonNodeExporterWithinHold, ReasonNodeExporterSingleView,
		ReasonNodeExporterBothViews, ReasonNodeExporterViewsSplit,
		ReasonAlertClockSkew, ReasonEvaluationClockBackwards, ReasonUnmappedHost,
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	return all
}

// Bounds on every input string that can reach the output. The decoder and the
// engine enforce them; the verdict schema carries the same patterns.
var (
	// NamePattern bounds an alert name; anything else is reported as Unnamed.
	NamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_:]{0,127}$`)
	// SeverityLabelPattern bounds source_severity; anything else becomes null.
	SeverityLabelPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	// SlugPattern bounds host and replica values; anything else is Unmapped.
	SlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	// IDPattern bounds a policy rule or hold id.
	IDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// Literals reported in place of a value that fails its bound.
const (
	Unnamed  = "unnamed"
	Unmapped = "unmapped"
)

// SourceState is the state of an alert source in the verdict.
type SourceState string

// Source states.
const (
	SourceOK          SourceState = "ok"
	SourceUnreachable SourceState = "unreachable"
	SourceStale       SourceState = "stale"
)

// AlertState is the Alertmanager state of an alert, kept finer than the
// verdict's collapsed status so the engine can name silenced versus inhibited.
type AlertState string

// Alert states as the decoder produces them.
const (
	StateActive      AlertState = "active"
	StateSilenced    AlertState = "silenced"
	StateInhibited   AlertState = "inhibited"
	StateUnprocessed AlertState = "unprocessed" // classified like active
)

// Status is the collapsed state shown in the verdict.
type Status string

// Verdict statuses.
const (
	StatusActive     Status = "active"
	StatusSuppressed Status = "suppressed"
)

// Alert is one Alertmanager alert after decoding.
//
// Labels holds the raw label set. It is used only for matching and is never
// written to any output. Name and SourceSeverity are bounded by the decoder.
// Host and replica values are resolved by the engine from Labels, because the
// label names come from the policy (host_label, replica_label), which the
// decoder does not see; the engine uses ResolveSlug for that.
type Alert struct {
	Name           string            // alertname if it matches NamePattern, else Unnamed
	Labels         map[string]string // raw labels; matching only, never output
	SourceSeverity *string           // the severity label if it matches SeverityLabelPattern, else nil
	State          AlertState
	StartsAt       time.Time
	UpdatedAt      time.Time
}

// Snapshot is one read of an alert source.
type Snapshot struct {
	SourceID string      // "file" for evaluate
	State    SourceState // ok, unreachable or stale
	LastOK   *time.Time  // nil when never ok
	Alerts   []Alert     // nil or empty counts as "Watchdog not seen"
}

// Matcher matches one label value: equality, or an anchored regex.
type Matcher struct {
	Equals string         // used when Regex is nil
	Regex  *regexp.Regexp // already anchored by the parser
}

// Matches reports whether v satisfies the matcher.
func (m Matcher) Matches(v string) bool {
	if m.Regex != nil {
		return m.Regex.MatchString(v)
	}
	return v == m.Equals
}

// Match maps a label name to its matcher. Every entry must match.
type Match map[string]Matcher

// Matches reports whether labels satisfy every matcher. A missing label never
// matches, and an empty Match matches nothing (the schema requires one key).
func (m Match) Matches(labels map[string]string) bool {
	if len(m) == 0 {
		return false
	}
	for k, matcher := range m {
		v, ok := labels[k]
		if !ok || !matcher.Matches(v) {
			return false
		}
	}
	return true
}

// EscalateHosts says which hosts an escalation applies to.
type EscalateHosts string

// Escalation scopes.
const (
	HostsFirstClass EscalateHosts = "first_class"
	HostsAll        EscalateHosts = "all"
)

// Escalate raises a matched alert to RED once it is old enough.
type Escalate struct {
	After time.Duration // already resolved; "node_exporter_red_hold" becomes the policy's value
	Hosts EscalateHosts
}

// Rule classifies matching alerts. Every matching rule applies and the worst
// severity wins.
type Rule struct {
	ID       string
	Match    Match
	Severity Severity // YELLOW or RED
	Escalate *Escalate
}

// HoldKind is the kind of a hold.
type HoldKind string

// Hold kinds.
const (
	HoldExpectedDark  HoldKind = "expected_dark"
	HoldKnown         HoldKind = "known_hold"
	HoldAnnouncedDark HoldKind = "announced_dark"
)

// Hold exempts matching alerts from raising overall.
type Hold struct {
	ID        string
	Match     Match
	Kind      HoldKind
	ExpiresAt time.Time // set for announced_dark only
}

// Watchdog configures the heartbeat.
type Watchdog struct {
	AlertName     string
	DeadmanWindow time.Duration
}

// Policy is a parsed, validated policy. Defaults are already applied:
// HostLabel "host", ReplicaLabel "replica", NodeExporterRedHold 10m,
// Watchdog.DeadmanWindow 5m. Replicas is nil when the key is unset
// (single-view mode); an empty non-nil slice never occurs.
type Policy struct {
	Default             Severity // YELLOW or RED
	HostLabel           string
	ReplicaLabel        string
	Replicas            []string
	Watchdog            Watchdog
	NodeExporterRedHold time.Duration
	FirstClassHosts     []string
	Rules               []Rule
	Holds               []Hold
	SHA256              string // lowercase hex of the exact policy bytes, set by the parser
}

// FieldError is one problem in an input file, in the form the renderers need:
// where it is, what was there, what is wrong and how to fix it. Value is the
// raw excerpt; the renderer truncates it and strips control characters.
type FieldError struct {
	Line    int    // 1-based, 0 when unknown
	Path    string // field path, for example rules[2].match
	Value   string // raw offending text, may be long
	Problem string // what is wrong
	Fix     string // how to fix it
}

// Verdict is the verdict document. render.JSON owns the canonical byte form;
// the engine fills the struct with every slice already sorted and never nil.
type Verdict struct {
	APIVersion   string
	GeneratedAt  time.Time
	TimeSource   string // "flag" or "wall"; set by the caller, the engine never reads a clock
	Overall      Severity
	PolicySHA256 string
	Reasons      []Reason
	Watchdog     WatchdogState
	Sources      []Source
	Alerts       []VerdictAlert
}

// VerdictAPIVersion is the value of Verdict.APIVersion.
const VerdictAPIVersion = "augur.verdict/v0"

// Time sources for Verdict.TimeSource.
const (
	TimeFlag = "flag"
	TimeWall = "wall"
)

// WatchdogState is the verdict's heartbeat block.
type WatchdogState struct {
	Seen     bool
	LastSeen *time.Time // nil when not seen
}

// Source is one entry of the verdict's sources array.
type Source struct {
	ID         string
	State      SourceState
	LastOK     *time.Time
	AlertCount int
}

// VerdictAlert is one alert in the verdict.
type VerdictAlert struct {
	Name           string
	Host           string
	Severity       Severity
	SourceSeverity *string
	Expected       bool
	Status         Status
	StartsAt       time.Time
	Replicas       []string
	RuleID         *string
	Reasons        []Reason
}

// ResolveSlug returns v if it matches SlugPattern, else Unmapped, and whether
// it matched.
func ResolveSlug(v string) (string, bool) {
	if SlugPattern.MatchString(v) {
		return v, true
	}
	return Unmapped, false
}
