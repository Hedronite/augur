package serve

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"testing"
	"time"
)

const (
	soakPolls    = 1000
	soakBaseline = 100
	soakHeapSlop = 0.10 // heap after the last poll may exceed the baseline by at most this fraction
)

// soakBody is the body of MaxAlerts alerts: a fresh Watchdog (rebuilt per
// request, so it never ages past the dead-man window as the clock advances)
// plus MaxAlerts-1 distinct (name, host) alerts, so the verdict is as large as
// a poll can make it. Some are silenced or inhibited to exercise every branch.
func soakBody(m *am) func() []string {
	states := []string{"active", "active", "active", "suppressed", "unprocessed"}
	rest := make([]string, 0, MaxAlerts-1)
	for i := 0; i < MaxAlerts-1; i++ {
		host := fmt.Sprintf("host-%c", 'a'+byte(i%5))
		st := states[i%len(states)]
		rest = append(rest, fmt.Sprintf(
			`{"labels":{"alertname":"Alert%04d","host":%q,"severity":"warning"},"annotations":{"summary":"synthetic soak alert"},"startsAt":"2025-12-01T00:00:00Z","endsAt":"0001-01-01T00:00:00Z","updatedAt":"2026-01-15T11:59:00Z","fingerprint":"soak%04d","status":{"state":%q,"silencedBy":[],"inhibitedBy":[]}}`,
			i/5, host, i, st))
	}
	return func() []string { return append([]string{m.watchdog(10 * time.Second)}, rest...) }
}

// alwaysEnabled keeps a discarding handler switched on, so pollSignal still
// sees every record (slog skips a handler that reports itself disabled).
type alwaysEnabled struct{ slog.Handler }

func (alwaysEnabled) Enabled(context.Context, slog.Level) bool { return true }

func settledHeap() uint64 {
	var m runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// TestSoak runs serve for soakPolls polls at MaxAlerts alerts, with an
// injected clock, and fails if memory or goroutines grow: the heap after the
// last poll must be within 10% of the heap after poll 100, and the goroutine
// count must be the same. It is the leak check for a long-running daemon.
func TestSoak(t *testing.T) {
	if testing.Short() {
		t.Skip("soak test skipped in -short mode")
	}
	if raceEnabled {
		t.Skip("the soak runs without -race (make soak): the race detector multiplies its run time about tenfold")
	}
	// A discarding logger: the harness's own log buffer would otherwise grow
	// with every poll and read as a leak.
	h := startHarness(t, func(h *harness) {
		h.deps.Logger = slog.New(pollSignal{Handler: alwaysEnabled{slog.DiscardHandler}, ch: h.polled})
	})
	h.am.setBody(soakBody(h.am))

	var heapBase uint64
	var goBase int
	start := time.Now()
	for i := 1; i <= soakPolls; i++ {
		h.clock.Set(t0.Add(time.Duration(i) * 30 * time.Second))
		h.ticks <- h.clock.Now()
		h.waitWrite()
		if i == soakBaseline {
			heapBase, goBase = settledHeap(), runtime.NumGoroutine()
		}
	}
	heapEnd, goEnd := settledHeap(), runtime.NumGoroutine()
	t.Logf("%d polls of %d alerts in %v; heap after poll %d: %d B, after poll %d: %d B; goroutines %d -> %d",
		soakPolls, MaxAlerts, time.Since(start).Round(time.Millisecond), soakBaseline, heapBase, soakPolls, heapEnd, goBase, goEnd)

	if limit := float64(heapBase) * (1 + soakHeapSlop); float64(heapEnd) > limit {
		t.Errorf("heap grew: %d B after poll %d, %d B after poll %d (limit %.0f B)", heapBase, soakBaseline, heapEnd, soakPolls, limit)
	}
	if goEnd != goBase {
		t.Errorf("goroutines not flat: %d after poll %d, %d after poll %d", goBase, soakBaseline, goEnd, soakPolls)
	}
	v := h.read()
	if len(v.Alerts) < MaxAlerts-1 || v.Sources[0].AlertCount != MaxAlerts {
		t.Errorf("the soak did not exercise MaxAlerts: %d verdict alerts, alert_count %d", len(v.Alerts), v.Sources[0].AlertCount)
	}
}
