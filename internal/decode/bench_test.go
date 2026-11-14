package decode

import (
	"strconv"
	"strings"
	"testing"
)

// bodyBudget is the 16 MiB body cap that `evaluate` and `serve` share, so a
// benchmark at this size is the per-poll cost the loop actually pays.
const bodyBudget = 16 << 20

// BenchAlertNames are the real rule names; only the hosts are synthetic.
var benchAlertNames = []string{
	"Watchdog", "NodeExporterDown", "PeerPrometheusDown", "PeerPrometheusAbsent",
	"SSHFailure", "DiskSpaceWarning", "DiskSpaceCritical", "TargetDown",
}

// benchHosts are the synthetic hosts used everywhere else in the repo.
var benchHosts = []string{"host-a", "host-b", "host-c", "host-d", "host-e"}

// BenchmarkDecodeAM16MiB measures decoding one full body of realistic
// Alertmanager alerts: the shape a poll of a busy mesh returns.
func BenchmarkDecodeAM16MiB(b *testing.B) {
	data := realisticBody(b, bodyBudget)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		snap, err := DecodeAM(data)
		if err != nil {
			b.Fatalf("DecodeAM: %v", err)
		}
		if len(snap.Alerts) == 0 {
			b.Fatal("decoded no alerts")
		}
	}
}

// BenchmarkDecodeAM16MiBDense measures the worst case for the alert count: the
// smallest alert the schema accepts, repeated until the body budget is spent.
// It is the input that maximises how many verdict entries a poll can produce.
func BenchmarkDecodeAM16MiBDense(b *testing.B) {
	data := denseBody(b, bodyBudget)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		snap, err := DecodeAM(data)
		if err != nil {
			b.Fatalf("DecodeAM: %v", err)
		}
		if len(snap.Alerts) == 0 {
			b.Fatal("decoded no alerts")
		}
	}
}

// realisticBody builds an alerts array of about budget bytes with every field a
// real Alertmanager alert carries.
func realisticBody(tb testing.TB, budget int) []byte {
	tb.Helper()
	var b strings.Builder
	b.Grow(budget + 4096)
	b.WriteByte('[')
	for i := 0; b.Len() < budget; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		name := benchAlertNames[i%len(benchAlertNames)]
		host := benchHosts[i%len(benchHosts)]
		replica := "r1"
		if i%2 == 1 {
			replica = "r2"
		}
		state := `{"state":"active"}`
		if i%17 == 0 {
			state = `{"state":"suppressed","silencedBy":["silence-` + strconv.Itoa(i) + `"]}`
		}
		b.WriteString(`{"labels":{"alertname":"` + name + `","host":"` + host +
			`","instance":"` + host + `:9100","job":"node","replica":"` + replica +
			`","severity":"warning"},"annotations":{"summary":"` + name + ` on ` + host +
			`","description":"the exporter stopped reporting on ` + host + `"},"startsAt":"2026-01-15T11:` +
			twoDigits(i%60) + `:00Z","endsAt":"0001-01-01T00:00:00Z","updatedAt":"2026-01-15T11:58:00Z","fingerprint":"` +
			strconv.FormatInt(int64(i), 16) + `","generatorURL":"https://example.invalid/graph?g0.expr=up","status":` +
			state + `}`)
	}
	b.WriteByte(']')
	return []byte(b.String())
}

// denseBody builds the smallest alert the schema accepts, repeated until the
// budget is spent or the alert cap is reached, whichever comes first. At this
// size the cap is what stops it: 16 MiB holds roughly 174 000 minimal alerts
// and MaxAlerts is 100 000.
func denseBody(tb testing.TB, budget int) []byte {
	tb.Helper()
	const one = `{"labels":{"alertname":"A"},"startsAt":"2026-01-15T11:00:00Z","status":{"state":"active"}}`
	var b strings.Builder
	b.Grow(budget + 4096)
	b.WriteByte('[')
	b.WriteString(one)
	for count := 1; count < MaxAlerts && b.Len()+1+len(one) < budget; count++ {
		b.WriteByte(',')
		b.WriteString(one)
	}
	b.WriteByte(']')
	return []byte(b.String())
}

// twoDigits renders 0..59 with a leading zero.
func twoDigits(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}
