package render

import (
	"encoding/json"
	"io"
	"time"

	"github.com/Hedronite/augur/internal/model"
)

// canonical is the wire form of a verdict. It mirrors the schema key order
// and holds times as pre-formatted strings, so encoding/json cannot drift
// from the contract: no nanosecond formatting, no time-zone variance, and
// null only where the schema allows it.
//
// Field order here is load-bearing: encoding/json emits struct fields in
// declaration order, and this order is schema/verdict.v0.json's property
// order. The A0 conformance test compares against the expected.json fixtures
// byte for byte.
type canonical struct {
	Schema       string            `json:"schema"`
	GeneratedAt  string            `json:"generated_at"`
	TimeSource   string            `json:"time_source"`
	Overall      string            `json:"overall"`
	PolicySHA256 string            `json:"policy_sha256"`
	Reasons      []string          `json:"reasons"`
	Watchdog     canonicalWatchdog `json:"watchdog"`
	Sources      []canonicalSource `json:"sources"`
	Alerts       []canonicalAlert  `json:"alerts"`
}

// canonicalWatchdog carries last_seen as any so an unseen heartbeat is JSON
// null, not an empty string.
type canonicalWatchdog struct {
	Seen     bool `json:"seen"`
	LastSeen any  `json:"last_seen"`
}

type canonicalSource struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	LastOK     any    `json:"last_ok"`
	AlertCount int    `json:"alert_count"`
}

type canonicalAlert struct {
	Name           string   `json:"name"`
	Host           string   `json:"host"`
	Severity       string   `json:"severity"`
	SourceSeverity *string  `json:"source_severity"`
	Expected       bool     `json:"expected"`
	Status         string   `json:"status"`
	StartsAt       string   `json:"starts_at"`
	Replicas       []string `json:"replicas"`
	RuleID         *string  `json:"rule_id"`
	Reasons        []string `json:"reasons"`
}

// rfc3339 formats t as UTC RFC3339 with second precision, matching the
// fixtures. Sub-second precision is dropped so output stays byte-stable.
func rfc3339(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// nullableTime maps *time.Time to a JSON string or nil (null).
func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return rfc3339(*t)
}

// strList copies a reason slice, guaranteeing [] rather than null for empty.
func strList(reasons []model.Reason) []string {
	out := make([]string, len(reasons))
	for i, r := range reasons {
		out[i] = string(r)
	}
	return out
}

// strSlice guarantees [] rather than null for empty string slices.
func strSlice(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func newCanonical(v model.Verdict) canonical {
	sources := make([]canonicalSource, len(v.Sources))
	for i, s := range v.Sources {
		sources[i] = canonicalSource{
			ID:         s.ID,
			State:      string(s.State),
			LastOK:     nullableTime(s.LastOK),
			AlertCount: s.AlertCount,
		}
	}

	alerts := make([]canonicalAlert, len(v.Alerts))
	for i, a := range v.Alerts {
		alerts[i] = canonicalAlert{
			Name:           a.Name,
			Host:           a.Host,
			Severity:       string(a.Severity),
			SourceSeverity: a.SourceSeverity,
			Expected:       a.Expected,
			Status:         string(a.Status),
			StartsAt:       rfc3339(a.StartsAt),
			Replicas:       strSlice(a.Replicas),
			RuleID:         a.RuleID,
			Reasons:        strList(a.Reasons),
		}
	}

	return canonical{
		Schema:       model.VerdictSchema,
		GeneratedAt:  rfc3339(v.GeneratedAt),
		TimeSource:   v.TimeSource,
		Overall:      string(v.Overall),
		PolicySHA256: v.PolicySHA256,
		Reasons:      strList(v.Reasons),
		Watchdog: canonicalWatchdog{
			Seen:     v.Watchdog.Seen,
			LastSeen: nullableTime(v.Watchdog.LastSeen),
		},
		Sources: sources,
		Alerts:  alerts,
	}
}

// JSON writes the canonical verdict document: keys in schema order, UTC
// RFC3339 times with second precision, null for nil pointers, [] (never
// null) for empty slices, two-space indent, HTML characters unescaped, and
// a trailing newline. The same verdict always produces the same bytes.
func JSON(w io.Writer, v model.Verdict) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(newCanonical(v))
}
