package engine_test

import (
	"testing"
	"time"

	"github.com/Hedronite/augur/internal/engine"
	"github.com/Hedronite/augur/internal/model"
)

// TestHeartbeatNeverReportsUnmappedHost: the Watchdog carries no host label, so
// its host is the literal `unmapped` and that is not an anomaly to report.
// A non-heartbeat alert whose host cannot be read still reports unmapped_host,
// which fixture 61 pins.
func TestHeartbeatNeverReportsUnmappedHost(t *testing.T) {
	v := engine.Evaluate(snap(alert("Watchdog", "", 24*time.Hour)), testPolicy(nil), now)
	wd := find(t, v, "Watchdog")
	if wd.Host != model.Unmapped {
		t.Fatalf("heartbeat host = %q, want %q", wd.Host, model.Unmapped)
	}
	if has(wd.Reasons, model.ReasonUnmappedHost) {
		t.Fatalf("heartbeat reasons = %v, want none of them unmapped_host", wd.Reasons)
	}
	if !has(wd.Reasons, model.ReasonHeartbeat) {
		t.Fatalf("heartbeat reasons = %v, want heartbeat", wd.Reasons)
	}
	if v.Overall != model.Green {
		t.Fatalf("overall = %q, want GREEN", v.Overall)
	}

	v = engine.Evaluate(snap(watchdog(), alert("NodeExporterDown", "Host_A", 3*time.Minute)), testPolicy(nil), now)
	ne := find(t, v, "NodeExporterDown")
	if !has(ne.Reasons, model.ReasonUnmappedHost) {
		t.Fatalf("non-heartbeat reasons = %v, want unmapped_host", ne.Reasons)
	}
}
