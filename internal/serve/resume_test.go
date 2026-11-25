package serve

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Hedronite/augur/internal/decode"
	"github.com/Hedronite/augur/internal/model"
	"github.com/Hedronite/augur/internal/policy"
)

// manyAlerts serves a Watchdog-free array of n alerts.
func manyAlerts(n int) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		out := make([]string, n)
		for i := range out {
			if n > decode.MaxAlerts {
				// Refused on count alone, so keep the body small and quick.
				out[i] = "{}"
				continue
			}
			out[i] = fmt.Sprintf(`{"labels":{"alertname":"A%d"},"startsAt":"2025-12-01T00:00:00Z","status":{"state":"active"}}`, i)
		}
		_, _ = io.WriteString(w, "["+strings.Join(out, ",")+"]")
	}
}

// Over the poll cap, or over the decoder's own cap: alerts_over_cap, never
// "unreachable", never GREEN, and still blind once the window passes.
func TestOverCapIsItsOwnReason(t *testing.T) {
	for _, n := range []int{MaxAlerts + 1, decode.MaxAlerts + 1} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			h := startHarness(t, nil)
			h.am.set(manyAlerts(n))
			check := func(v verdictDoc, overall string) {
				t.Helper()
				if v.Overall != overall || v.Observed == nil || *v.Observed || !has(v.Reasons, "alerts_over_cap") ||
					has(v.Reasons, "alertmanager_unreachable") || has(v.Reasons, "alertmanager_stale") ||
					(!has(v.Reasons, "watchdog_missing") && !has(v.Reasons, "observability_blind")) {
					t.Fatalf("%+v observed %v", v, v.Observed)
				}
				if v.Sources[0].State != "stale" || v.Sources[0].AlertCount != 0 || len(v.Alerts) != 0 || v.Watchdog.Seen {
					t.Fatalf("an over-cap poll evaluates nothing: %+v", v)
				}
				if v.Sources[0].LastOK == nil || *v.Sources[0].LastOK != "2026-01-15T12:00:00Z" {
					t.Fatalf("last_ok must stay at the last good poll: %v", v.Sources[0].LastOK)
				}
			}
			check(h.tick(10*time.Second), "YELLOW")
			if !strings.Contains(h.logs.String(), `"error_kind":"`+KindTooMany+`"`) {
				t.Fatalf("log should name the kind:\n%s", h.logs.String())
			}
			check(h.tick(5*time.Minute), "RED")
			h.am.setBody(func() []string { return []string{h.am.watchdog(time.Second)} })
			if v := h.tick(6 * time.Minute); v.Overall != "GREEN" || v.Observed == nil || !*v.Observed || has(v.Reasons, "alerts_over_cap") {
				t.Fatalf("recovery: %+v", v)
			}
		})
	}
}

// Exactly the cap is still evaluated.
func TestAtTheCapIsEvaluated(t *testing.T) {
	h := startHarness(t, nil)
	h.am.set(manyAlerts(MaxAlerts))
	v := h.tick(10 * time.Second)
	if v.Observed == nil || !*v.Observed || has(v.Reasons, "alerts_over_cap") || len(v.Alerts) != MaxAlerts {
		t.Fatalf("reasons %v alerts %d", v.Reasons, len(v.Alerts))
	}
}

func TestHeaderFields(t *testing.T) {
	h := startHarness(t, nil)
	v := h.read()
	if v.Observed == nil || !*v.Observed || string(v.ValidFor) != "60" || string(v.Declaration) != "null" || v.Watchdog.DeadmanSince != nil {
		t.Fatalf("healthy: observed %v valid_for %s declaration %s since %v", v.Observed, v.ValidFor, v.Declaration, v.Watchdog.DeadmanSince)
	}

	digest := "sha256:" + strings.Repeat("b", 64)
	f := &flaky{inner: NewHTTPClient()}
	f.down.Store(true)
	h = startHarness(t, func(h *harness) {
		pol, errs := policy.Parse([]byte(testPolicy + "declaration: " + digest + "\n"))
		if len(errs) > 0 {
			t.Fatalf("policy: %+v", errs)
		}
		h.cfg.Policy, h.cfg.Interval, h.deps.Client = pol, 5500*time.Millisecond, f
	})
	v = h.read()
	// Never connected: unobserved, yet the header is complete. 2 x 5.5s = 11.
	if v.Observed == nil || *v.Observed || string(v.ValidFor) != "11" || string(v.Declaration) != `"`+digest+`"` ||
		v.Overall != "YELLOW" || v.Watchdog.DeadmanSince == nil || *v.Watchdog.DeadmanSince != "2026-01-15T12:00:00Z" {
		t.Fatalf("down: observed %v valid_for %s declaration %s %+v", v.Observed, v.ValidFor, v.Declaration, v)
	}
}

func TestValidForIsTwiceTheIntervalRoundedDown(t *testing.T) {
	for in, want := range map[time.Duration]int{
		0: 1, 5 * time.Second: 10, 5250 * time.Millisecond: 10, 30 * time.Second: 60, time.Minute: 120,
	} {
		if got := validFor(in); got != want {
			t.Errorf("validFor(%v) = %d, want %d", in, got, want)
		}
	}
}

// stop ends a run and waits for it, so another can take over its --out.
func (h *harness) stop() {
	h.t.Helper()
	h.cancel()
	if err := <-h.done; err != nil {
		h.t.Fatal(err)
	}
	h.done <- nil // for the cleanup
}

// restart starts a new run at t0+at on the same --out.
func restart(t *testing.T, out string, at time.Duration, body func(*am) string, mutate func(*harness)) *harness {
	t.Helper()
	return startHarness(t, func(h *harness) {
		h.out, h.cfg.Out = out, out
		h.clock.Set(t0.Add(at))
		h.am.setBody(func() []string { return []string{body(h.am)} })
		if mutate != nil {
			mutate(h)
		}
	})
}

func peerOnly(a *am) string {
	return a.alert("PeerPrometheusDown", "host-b", "2026-01-15T11:59:00Z", "")
}

func expect(t *testing.T, v verdictDoc, overall, reason string) {
	t.Helper()
	if v.Overall != overall || !has(v.Reasons, reason) {
		t.Fatalf("at %s: %s %v, want %s with %s", v.GeneratedAt, v.Overall, v.Reasons, overall, reason)
	}
}

// The window carries on across restarts, even several of them, while the
// source answers but the heartbeat is missing: the last heartbeat was at t0.
func TestRestartKeepsDeadmanTiming(t *testing.T) {
	h := startHarness(t, nil)
	h.am.setBody(func() []string { return []string{peerOnly(h.am)} })
	expect(t, h.tick(2*time.Minute), "YELLOW", "watchdog_missing")
	h.stop()

	h = restart(t, h.out, 3*time.Minute, peerOnly, nil)
	expect(t, h.read(), "YELLOW", "watchdog_missing")
	if s := h.read().Watchdog.DeadmanSince; s == nil || *s != "2026-01-15T12:00:00Z" {
		t.Fatalf("deadman_since = %v", s)
	}
	h.stop()

	h = restart(t, h.out, 4*time.Minute, peerOnly, nil)
	expect(t, h.tick(5*time.Minute-time.Second), "YELLOW", "watchdog_missing")
	expect(t, h.tick(5*time.Minute), "RED", "observability_blind")
	if !strings.Contains(h.logs.String(), `"msg":"resume"`) {
		t.Fatalf("no resume line:\n%s", h.logs.String())
	}
}

// A blind verdict stays blind through a restart, and a heartbeat clears it.
func TestRestartStaysBlindUntilAHeartbeat(t *testing.T) {
	h := startHarness(t, nil)
	h.am.setBody(func() []string { return []string{peerOnly(h.am)} })
	expect(t, h.tick(6*time.Minute), "RED", "observability_blind")
	h.stop()

	h = restart(t, h.out, 7*time.Minute, peerOnly, nil)
	expect(t, h.read(), "RED", "observability_blind")
	h.stop()

	h = restart(t, h.out, 8*time.Minute, func(a *am) string { return a.watchdog(time.Second) }, nil)
	expect(t, h.read(), "GREEN", "watchdog_only")
}

// Unreachable before and after: the window runs from the last heartbeat.
func TestRestartWhileUnreachable(t *testing.T) {
	down := func(h *harness) {
		f := &flaky{inner: NewHTTPClient()}
		f.down.Store(true)
		h.deps.Client = f
	}
	h := startHarness(t, nil)
	h.am.set(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", http.StatusInternalServerError) })
	expect(t, h.tick(time.Minute), "YELLOW", "alertmanager_unreachable")
	h.stop()

	h = restart(t, h.out, 2*time.Minute, peerOnly, down)
	expect(t, h.tick(5*time.Minute-time.Second), "YELLOW", "alertmanager_unreachable")
	expect(t, h.tick(5*time.Minute), "RED", "observability_blind")
}

// After a healthy verdict the window runs from that verdict.
func TestRestartAfterHealthy(t *testing.T) {
	h := startHarness(t, nil)
	expect(t, h.tick(time.Minute), "GREEN", "watchdog_only")
	h.stop()

	h = restart(t, h.out, 2*time.Minute, peerOnly, nil)
	expect(t, h.read(), "YELLOW", "watchdog_missing")
	expect(t, h.tick(6*time.Minute-time.Second), "YELLOW", "watchdog_missing")
	expect(t, h.tick(6*time.Minute), "RED", "observability_blind")
}

// No usable last verdict: the start is a first run, and it is not an error.
func TestRestartWithoutAUsableVerdict(t *testing.T) {
	cases := map[string]func(t *testing.T, path string){
		"absent":       func(*testing.T, string) {},
		"empty":        writeFile(""),
		"not JSON":     writeFile("old verdict\n"),
		"truncated":    writeFile(`{"apiVersion":"augur.verdict/v0","reasons":["observability_blind"]`),
		"wrong types":  writeFile(`{"apiVersion":"augur.verdict/v0","generated_at":7}`),
		"other major":  writeFile(strings.Replace(blindDoc, "verdict/v0", "verdict/v9", 1)),
		"evaluate":     writeFile(strings.Replace(blindDoc, `"wall"`, `"flag"`, 1)),
		"file source":  writeFile(strings.Replace(blindDoc, `"id":"alertmanager"`, `"id":"file"`, 1)),
		"over the cap": writeFile(blindDoc + strings.Repeat(" ", MaxVerdictBytes)),
	}
	for name, prepare := range cases {
		t.Run(name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "verdict.json")
			prepare(t, out)
			h := restart(t, out, time.Hour, peerOnly, nil)
			expect(t, h.read(), "YELLOW", "watchdog_missing")
			if got := strings.Contains(h.logs.String(), `"kind":"unusable_verdict"`); got != (name != "absent") {
				t.Fatalf("warned = %v:\n%s", got, h.logs.String())
			}
		})
	}
	// The same document, unchanged, is usable: the cases above fail on their own change.
	out := filepath.Join(t.TempDir(), "verdict.json")
	writeFile(blindDoc)(t, out)
	expect(t, restart(t, out, time.Hour, peerOnly, nil).read(), "RED", "observability_blind")
}

const blindDoc = `{"apiVersion":"augur.verdict/v0","generated_at":"2026-01-15T12:00:00Z","time_source":"wall",` +
	`"reasons":["observability_blind"],"watchdog":{"seen":false,"last_seen":null},` +
	`"sources":[{"id":"alertmanager","state":"ok","last_ok":"2026-01-15T12:00:00Z"}]}`

func writeFile(body string) func(*testing.T, string) {
	return func(t *testing.T, path string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// A pipe or directory at --out is refused without being opened.
func TestReadPriorRefusesNonRegularFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{fifo, dir} {
		if _, err := readPrior(p); !errors.Is(err, errNotServeVerdict) {
			t.Errorf("readPrior(%s) = %v", filepath.Base(p), err)
		}
	}
}

func TestDeadmanSince(t *testing.T) {
	const window = 5 * time.Minute
	start := t0.Add(time.Hour)
	at := func(d time.Duration) string { return t0.Add(d).Format(time.RFC3339) }
	doc := func(generated time.Duration, watchdog, reasons, state string, lastOK time.Duration) []byte {
		return []byte(fmt.Sprintf(`{"apiVersion":%q,"generated_at":%q,"time_source":"wall","reasons":[%s],"watchdog":{%s},`+
			`"sources":[{"id":"alertmanager","state":%q,"last_ok":%q}]}`,
			model.VerdictAPIVersion, at(generated), reasons, watchdog, state, at(lastOK)))
	}
	cases := []struct {
		name string
		doc  []byte
		want time.Time
	}{
		{"recorded", doc(10*time.Minute, `"seen":false,"deadman_since":"`+at(8*time.Minute)+`"`, "", "ok", 10*time.Minute), t0.Add(8 * time.Minute)},
		{"healthy", doc(10*time.Minute, `"seen":true`, "", "ok", 10*time.Minute), t0.Add(10 * time.Minute)},
		{"older release, unreachable", doc(10*time.Minute, `"seen":false`, "", "unreachable", 7*time.Minute), t0.Add(7 * time.Minute)},
		{"older release, missing", doc(10*time.Minute, `"seen":false`, "", "ok", 10*time.Minute), t0.Add(10 * time.Minute)},
		{"older release, blind", doc(59*time.Minute, `"seen":false`, `"observability_blind"`, "ok", 59*time.Minute), start.Add(-window)},
		{"from the future", doc(2*time.Hour, `"seen":true`, "", "ok", 2*time.Hour), start},
		{"blind and from the future", doc(2*time.Hour, `"seen":false`, `"observability_blind"`, "ok", 2*time.Hour), start.Add(-window)},
	}
	for _, c := range cases {
		got, err := deadmanSince(c.doc, window, start)
		if err != nil || !got.Equal(c.want) {
			t.Errorf("%s: %v %v, want %v", c.name, got, err, c.want)
		}
	}
}
