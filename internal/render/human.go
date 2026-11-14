package render

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Hedronite/augur/internal/model"
)

// Human writes the readable verdict: an overall line, the rollup of
// reasons, the heartbeat and source state, then one line per alert in the
// same order as the JSON (the engine sorts both from one slice). The output
// is plain text with no colour: a verdict must read identically in a pipe,
// a log and a terminal, so render never colours it.
func Human(out io.Writer, v model.Verdict) error {
	w := &errWriter{w: out}
	w.printf("OVERALL: %s\n", v.Overall)
	w.printf("reasons: %s\n", joinReasons(v.Reasons))
	w.printf("watchdog: %s\n", watchdogLine(v.Watchdog))
	w.printf("sources: %s\n", sourcesLine(v.Sources))

	if len(v.Alerts) == 0 {
		w.printf("alerts: none\n")
		return w.err
	}

	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "alerts:")
	for _, a := range v.Alerts {
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tsince %s\t%s\t%s\n",
			a.Severity, a.Name, a.Host, a.Status,
			a.StartsAt.UTC().Format(time.RFC3339),
			ruleCell(a.RuleID), reasonCell(a.Reasons))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	return w.err
}

// joinReasons renders a reason list as a comma-joined line, or "none".
func joinReasons(reasons []model.Reason) string {
	if len(reasons) == 0 {
		return "none"
	}
	parts := make([]string, len(reasons))
	for i, r := range reasons {
		parts[i] = string(r)
	}
	return strings.Join(parts, ", ")
}

func watchdogLine(ws model.WatchdogState) string {
	if ws.LastSeen != nil {
		return fmt.Sprintf("seen, last %s", ws.LastSeen.UTC().Format(time.RFC3339))
	}
	if ws.Seen {
		// Seen without a timestamp is a valid engine output for a heartbeat
		// with no updatedAt; show it without a time.
		return "seen"
	}
	return "not seen"
}

func sourcesLine(sources []model.Source) string {
	if len(sources) == 0 {
		return "none"
	}
	parts := make([]string, len(sources))
	for i, s := range sources {
		state := string(s.State)
		last := "never ok"
		if s.LastOK != nil {
			last = "last ok " + s.LastOK.UTC().Format(time.RFC3339)
		}
		parts[i] = fmt.Sprintf("%s %s (%d alerts, %s)", s.ID, state, s.AlertCount, last)
	}
	return strings.Join(parts, "; ")
}

func ruleCell(ruleID *string) string {
	if ruleID == nil {
		return "-"
	}
	return "rule " + *ruleID
}

func reasonCell(reasons []model.Reason) string {
	if len(reasons) == 0 {
		return "-"
	}
	parts := make([]string, len(reasons))
	for i, r := range reasons {
		parts[i] = string(r)
	}
	return "reasons " + strings.Join(parts, ",")
}
