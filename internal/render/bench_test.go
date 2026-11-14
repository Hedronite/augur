package render

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Hedronite/augur/internal/model"
)

// BenchmarkJSONLargest renders the widest verdict the contract allows: 4000
// alerts, the cap serve applies, with every bounded string at its maximum. It
// is the file size a consumer would have to read, not a typical one.
func BenchmarkJSONLargest(b *testing.B) {
	v := largestVerdict()
	var buf bytes.Buffer
	if err := JSON(&buf, v); err != nil {
		b.Fatalf("JSON: %v", err)
	}
	size := buf.Len()
	b.ReportMetric(float64(size), "B/verdict")
	b.ReportMetric(float64(size)/float64(len(v.Alerts)), "B/alert")
	b.Logf("largest verdict: %d bytes, %.0f B/alert over %d alerts", size, float64(size)/float64(len(v.Alerts)), len(v.Alerts))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := JSON(&buf, v); err != nil {
			b.Fatalf("JSON: %v", err)
		}
	}
}

// largestVerdict builds that verdict with bounded fields at their limits: a
// 128-character name, a 32-character host, a 31-character source severity, a
// 64-character rule id and three 32-character replicas.
func largestVerdict() model.Verdict {
	const count = 4000
	name := strings.Repeat("A", 128)
	host := strings.Repeat("h", 32)
	severity := "severity_" + strings.Repeat("s", 22)
	rule := strings.Repeat("r", 64)
	replicas := []string{strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)}
	reasons := []model.Reason{
		model.ReasonAlertClockSkew,
		model.ReasonNodeExporterBothViews,
		model.ReasonNodeExporterSingleView,
		model.ReasonNodeExporterViewsSplit,
		model.ReasonNodeExporterWithinHold,
		model.ReasonRuleMatched,
	}
	start := time.Date(2026, 1, 15, 11, 45, 0, 0, time.UTC)
	seen := time.Date(2026, 1, 15, 11, 58, 0, 0, time.UTC)

	alerts := make([]model.VerdictAlert, 0, count)
	for i := 0; i < count; i++ {
		rid := rule
		sev := severity
		alerts = append(alerts, model.VerdictAlert{
			Name:           name,
			Host:           host,
			Severity:       model.Red,
			SourceSeverity: &sev,
			Status:         model.StatusActive,
			StartsAt:       start,
			Replicas:       replicas,
			RuleID:         &rid,
			Reasons:        reasons,
		})
	}
	return model.Verdict{
		APIVersion:   model.VerdictAPIVersion,
		GeneratedAt:  start,
		TimeSource:   model.TimeFlag,
		Overall:      model.Red,
		PolicySHA256: strings.Repeat("0", 64),
		Reasons:      []model.Reason{},
		Watchdog:     model.WatchdogState{Seen: true, LastSeen: &seen},
		Sources:      []model.Source{{ID: "file", State: model.SourceOK, LastOK: &seen, AlertCount: count}},
		Alerts:       alerts,
	}
}
