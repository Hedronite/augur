package engine_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/Hedronite/augur/internal/engine"
	"github.com/Hedronite/augur/internal/model"
)

// benchNames and benchHosts keep the benchmark deterministic without touching
// testdata: the mix is what a mesh produces, not a fixture file.
var (
	benchNames = []string{"NodeExporterDown", "PeerPrometheusDown", "SSHFailure", "DiskSpaceCritical", "DiskSpaceWarning"}
	benchHosts = []string{"host-a", "host-b", "host-c", "host-d", "host-e"}
)

// benchSnapshot builds n alerts plus one Watchdog, cycling names and hosts, with
// a suppressed alert, a held expected-dark alert and a two-view report mixed in
// so the engine takes each path as it walks.
func benchSnapshot(n int) model.Snapshot {
	alerts := make([]model.Alert, 0, n+1)
	alerts = append(alerts, watchdog())
	for i := 0; i < n; i++ {
		a := alert(benchNames[i%len(benchNames)], benchHosts[i%len(benchHosts)], time.Duration(i%30)*time.Minute)
		switch i % 7 {
		case 0:
			a.State = model.StateSilenced
		case 1:
			a.Labels["port"] = "6443"
		case 2:
			a.Labels["replica"] = "r" + strconv.Itoa(i%2)
		case 3:
			a.Labels["host"] = "host-e"
		}
		alerts = append(alerts, a)
	}
	return snap(alerts...)
}

func benchEvaluate(b *testing.B, n int) {
	b.Helper()
	s := benchSnapshot(n)
	p := testPolicy([]string{"r0", "r1"})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := engine.Evaluate(s, p, now)
		if len(v.Alerts) == 0 {
			b.Fatal("evaluated no alerts")
		}
	}
}

// BenchmarkEvaluate9 is a quiet mesh: one Watchdog and eight alerts.
func BenchmarkEvaluate9(b *testing.B) { benchEvaluate(b, 8) }

// BenchmarkEvaluate4000 is serve's cap, the largest poll Augur classifies.
func BenchmarkEvaluate4000(b *testing.B) { benchEvaluate(b, 3999) }

// BenchmarkEvaluate100000 is evaluate's cap on a saved file.
func BenchmarkEvaluate100000(b *testing.B) { benchEvaluate(b, 99999) }
