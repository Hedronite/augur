// Package vigilmap turns an Augur verdict document into the two things Vigil
// takes from it: the verdicts[] entry and the augur{} block. It is the
// reference transform for docs/vigil.md. It is internal on purpose: the
// goldens under testdata/vigil are the contract between the two modules, and
// Vigil implements the mapping from the docs and checks itself against them.
//
// The input is the verdict JSON, not a Go value, because Vigil reads a file.
// The output is canonical: keys in schema order, two-space indent, a trailing
// newline, no map iteration anywhere, so the same verdict gives the same bytes.
package vigilmap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Versions and limits frozen by the block schema.
const (
	// VerdictAPIVersion is the only verdict version this transform reads.
	VerdictAPIVersion = "augur.verdict/v0"
	// BlockAPIVersion is the version of the augur{} block.
	BlockAPIVersion = "augur.vigil-block/v0"
	// Source is the Vigil authority slug for Augur.
	Source = "augur"
	// MaxAlerts caps alerts[] in the block.
	MaxAlerts = 50
)

// Block is the augur{} content, in schema key order.
type Block struct {
	APIVersion         string   `json:"apiVersion"`
	GeneratedAt        string   `json:"generated_at"`
	PolicySHA256       string   `json:"policy_sha256"`
	Watchdog           Watchdog `json:"watchdog"`
	AlertmanagerLastOK *string  `json:"alertmanager_last_ok"`
	Counts             Counts   `json:"counts"`
	Alerts             []Alert  `json:"alerts"`
	Omitted            int      `json:"omitted"`
}

// Watchdog is the heartbeat state.
type Watchdog struct {
	Seen     bool    `json:"seen"`
	LastSeen *string `json:"last_seen"`
}

// Counts partition every alert in the verdict by its effect on overall:
// total = raising.RED + raising.YELLOW + expected + suppressed.
type Counts struct {
	Total      int     `json:"total"`
	Raising    Raising `json:"raising"`
	Expected   int     `json:"expected"`
	Suppressed int     `json:"suppressed"`
}

// Raising counts the alerts that can raise overall, by severity.
type Raising struct {
	Red    int `json:"RED"`
	Yellow int `json:"YELLOW"`
}

// Alert is one raising alert as the block carries it.
type Alert struct {
	Name     string   `json:"name"`
	Host     string   `json:"host"`
	Severity string   `json:"severity"`
	StartsAt string   `json:"starts_at"`
	RuleID   *string  `json:"rule_id"`
	Replicas []string `json:"replicas"`
	Reasons  []string `json:"reasons"`
}

// Entry is the Vigil verdicts[] entry for a fresh file (state ok). Vigil adds
// its own codes and applies its stale cap; those are Vigil's fixtures.
type Entry struct {
	Source     string   `json:"source"`
	State      string   `json:"state"`
	Severity   string   `json:"severity"`
	Reasons    []string `json:"reasons"`
	ObservedAt string   `json:"observed_at"`
}

// verdictDoc mirrors the parts of the verdict this transform reads. Unknown
// fields are ignored, as Vigil ignores them.
type verdictDoc struct {
	APIVersion   string   `json:"apiVersion"`
	GeneratedAt  string   `json:"generated_at"`
	Overall      string   `json:"overall"`
	PolicySHA256 string   `json:"policy_sha256"`
	Reasons      []string `json:"reasons"`
	Watchdog     struct {
		Seen     bool    `json:"seen"`
		LastSeen *string `json:"last_seen"`
	} `json:"watchdog"`
	Sources []struct {
		LastOK *string `json:"last_ok"`
	} `json:"sources"`
	Alerts []verdictAlert `json:"alerts"`
}

type verdictAlert struct {
	Name     string   `json:"name"`
	Host     string   `json:"host"`
	Severity string   `json:"severity"`
	Expected bool     `json:"expected"`
	Status   string   `json:"status"`
	StartsAt string   `json:"starts_at"`
	Replicas []string `json:"replicas"`
	RuleID   *string  `json:"rule_id"`
	Reasons  []string `json:"reasons"`
}

// FromVerdictJSON maps a verdict document to the Vigil entry and block.
func FromVerdictJSON(data []byte) (Block, Entry, error) {
	var v verdictDoc
	if err := json.Unmarshal(data, &v); err != nil {
		return Block{}, Entry{}, fmt.Errorf("verdict is not valid JSON: %w", err)
	}
	if v.APIVersion != VerdictAPIVersion {
		return Block{}, Entry{}, errors.New("unknown verdict apiVersion")
	}
	switch v.Overall {
	case "GREEN", "YELLOW", "RED":
	default:
		return Block{}, Entry{}, errors.New("verdict overall is not GREEN, YELLOW or RED")
	}

	entry := Entry{
		Source:     Source,
		State:      "ok",
		Severity:   v.Overall,
		Reasons:    nonNil(v.Reasons),
		ObservedAt: v.GeneratedAt,
	}

	b := Block{
		APIVersion:   BlockAPIVersion,
		GeneratedAt:  v.GeneratedAt,
		PolicySHA256: v.PolicySHA256,
		Watchdog:     Watchdog{Seen: v.Watchdog.Seen, LastSeen: v.Watchdog.LastSeen},
		Alerts:       []Alert{},
	}
	if len(v.Sources) > 0 {
		b.AlertmanagerLastOK = v.Sources[0].LastOK
	}

	var raising []Alert
	b.Counts.Total = len(v.Alerts)
	for _, a := range v.Alerts {
		switch {
		case a.Expected:
			b.Counts.Expected++
		case a.Status == "suppressed":
			b.Counts.Suppressed++
		case a.Severity == "RED":
			b.Counts.Raising.Red++
			raising = append(raising, blockAlert(a))
		default:
			// YELLOW. A GREEN alert that is neither expected nor suppressed
			// cannot occur (policy defaults and rules are YELLOW or RED); if
			// one ever did, counting it as YELLOW is the fail-closed reading.
			b.Counts.Raising.Yellow++
			raising = append(raising, blockAlert(a))
		}
	}

	if err := sortAlerts(raising); err != nil {
		return Block{}, Entry{}, err
	}
	if len(raising) > MaxAlerts {
		b.Omitted = len(raising) - MaxAlerts
		raising = raising[:MaxAlerts]
	}
	if raising != nil {
		b.Alerts = raising
	}
	return b, entry, nil
}

func blockAlert(a verdictAlert) Alert {
	sev := "YELLOW"
	if a.Severity == "RED" {
		sev = "RED"
	}
	return Alert{
		Name: a.Name, Host: a.Host, Severity: sev, StartsAt: a.StartsAt,
		RuleID: a.RuleID, Replicas: nonNil(a.Replicas), Reasons: nonNil(a.Reasons),
	}
}

// sortAlerts orders by severity (RED first), starts_at ascending, host, name.
// (host, name) is unique in a verdict, so the order is total.
func sortAlerts(as []Alert) error {
	type keyed struct {
		a Alert
		t time.Time
	}
	ks := make([]keyed, len(as))
	for i, a := range as {
		t, err := time.Parse(time.RFC3339Nano, a.StartsAt)
		if err != nil {
			return fmt.Errorf("alert starts_at is not RFC3339: %w", err)
		}
		ks[i] = keyed{a: a, t: t}
	}
	sort.Slice(ks, func(x, y int) bool {
		a, b := ks[x], ks[y]
		if a.a.Severity != b.a.Severity {
			return a.a.Severity == "RED"
		}
		if !a.t.Equal(b.t) {
			return a.t.Before(b.t)
		}
		if a.a.Host != b.a.Host {
			return a.a.Host < b.a.Host
		}
		return a.a.Name < b.a.Name
	})
	for i := range ks {
		as[i] = ks[i].a
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// JSON returns the canonical bytes of the block.
func (b Block) JSON() ([]byte, error) { return canonical(b) }

// JSON returns the canonical bytes of the entry.
func (e Entry) JSON() ([]byte, error) { return canonical(e) }

func canonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
