package serve

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Hedronite/augur/internal/model"
	"github.com/Hedronite/augur/internal/render"
)

// TestVerdictFitsAtMaxAlerts shows the largest verdict one poll can produce
// stays under the reader's 4 MiB cap. Every input alert yields at most one
// verdict alert (alerts that merge only add a replica string, which is
// smaller), so MaxAlerts verdict alerts with every bounded field at its
// maximum is the worst case.
func TestVerdictFitsAtMaxAlerts(t *testing.T) {
	sev := strings.Repeat("s", 32)
	rule := strings.Repeat("r", 64)
	reasons := model.AllReasons()
	// The eight longest codes: more reasons than any alert can carry at once.
	longest := append([]model.Reason(nil), reasons...)
	for i := range longest {
		for j := i + 1; j < len(longest); j++ {
			if len(longest[j]) > len(longest[i]) {
				longest[i], longest[j] = longest[j], longest[i]
			}
		}
	}
	at := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	v := model.Verdict{
		Schema: model.VerdictSchema, GeneratedAt: at, TimeSource: model.TimeWall, Overall: model.Red,
		PolicySHA256: strings.Repeat("0", 64), Reasons: model.AllReasons(),
		Watchdog: model.WatchdogState{Seen: true, LastSeen: &at},
		Sources:  []model.Source{{ID: SourceID, State: model.SourceOK, LastOK: &at, AlertCount: MaxAlerts}},
	}
	for i := 0; i < MaxAlerts; i++ {
		v.Alerts = append(v.Alerts, model.VerdictAlert{
			Name: strings.Repeat("N", 128), Host: strings.Repeat("h", 32), Severity: model.Yellow,
			SourceSeverity: &sev, Status: model.StatusSuppressed, StartsAt: at,
			Replicas: []string{strings.Repeat("r", 32)}, RuleID: &rule, Reasons: longest[:8],
		})
	}
	var buf bytes.Buffer
	if err := render.JSON(&buf, v); err != nil {
		t.Fatal(err)
	}
	t.Logf("worst-case verdict at MaxAlerts=%d: %d bytes of %d", MaxAlerts, buf.Len(), MaxVerdictBytes)
	if buf.Len() > MaxVerdictBytes {
		t.Fatalf("a verdict at MaxAlerts is %d bytes, over the %d cap: lower MaxAlerts", buf.Len(), MaxVerdictBytes)
	}
}
