package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Hedronite/augur/internal/model"
	"github.com/Hedronite/augur/internal/policy"
)

const testPolicy = `schema: augur.policy/v0
default: YELLOW
watchdog:
  alertname: Watchdog
  deadman_window: 5m
rules:
  - id: peer-down
    match: { alertname: PeerPrometheusDown }
    severity: YELLOW
`

var t0 = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// fake Alertmanager. Each request builds its body from the fake clock.
type am struct {
	srv       *httptest.Server
	clock     *fakeClock
	mu        sync.Mutex
	handler   func(w http.ResponseWriter, r *http.Request)
	lastQuery string
	lastUA    string
	lastPath  string
	hits      atomic.Int64
}

func newAM(t *testing.T, clock *fakeClock) *am {
	t.Helper()
	a := &am{clock: clock}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.hits.Add(1)
		a.mu.Lock()
		a.lastQuery, a.lastUA, a.lastPath = r.URL.RawQuery, r.UserAgent(), r.URL.Path
		h := a.handler
		a.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(a.srv.Close)
	a.setBody(func() []string { return []string{a.watchdog(10 * time.Second)} })
	return a
}

func (a *am) set(h func(http.ResponseWriter, *http.Request)) {
	a.mu.Lock()
	a.handler = h
	a.mu.Unlock()
}

// setBody serves a 200 JSON array of the given alert objects.
func (a *am) setBody(alerts func() []string) {
	a.set(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "["+strings.Join(alerts(), ",")+"]")
	})
}

func (a *am) alert(name, host, updatedAgo string, extra string) string {
	return fmt.Sprintf(`{"labels":{"alertname":%q,"host":%q%s},"startsAt":"2025-12-01T00:00:00Z","endsAt":"0001-01-01T00:00:00Z","updatedAt":%q,"fingerprint":"f","status":{"state":"active"}}`,
		name, host, extra, updatedAgo)
}

// watchdog is a Watchdog whose updatedAt is ago before the fake clock.
func (a *am) watchdog(ago time.Duration) string {
	return a.alert("Watchdog", "host-a", a.clock.Now().Add(-ago).Format(time.RFC3339), "")
}

type verdictDoc struct {
	Overall    string   `json:"overall"`
	Reasons    []string `json:"reasons"`
	TimeSource string   `json:"time_source"`
	Watchdog   struct {
		Seen bool `json:"seen"`
	} `json:"watchdog"`
	Sources []struct {
		ID         string  `json:"id"`
		State      string  `json:"state"`
		LastOK     *string `json:"last_ok"`
		AlertCount int     `json:"alert_count"`
	} `json:"sources"`
	Alerts []struct {
		Name string `json:"name"`
	} `json:"alerts"`
}

type harness struct {
	t       *testing.T
	clock   *fakeClock
	am      *am
	ticks   chan time.Time
	written chan struct{}
	polled  chan struct{} // a "poll" log line was emitted
	done    chan error
	cancel  context.CancelFunc
	out     string
	logs    *syncBuf
	deps    *Deps
	cfg     Config
}

func startHarness(t *testing.T, mutate func(*harness)) *harness {
	t.Helper()
	clock := &fakeClock{t: t0}
	h := &harness{t: t, clock: clock, am: newAM(t, clock), ticks: make(chan time.Time), written: make(chan struct{}, 64), polled: make(chan struct{}, 64),
		done: make(chan error, 1), out: filepath.Join(t.TempDir(), "verdict.json"), logs: &syncBuf{}}
	pol, errs := policy.Parse([]byte(testPolicy))
	if len(errs) > 0 {
		t.Fatalf("policy: %+v", errs)
	}
	u, err := ParseAlertmanagerURL(h.am.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	h.cfg = Config{Policy: pol, URL: u, Out: h.out, Interval: 30 * time.Second, Version: "test"}
	h.deps = &Deps{
		Now:    clock.Now,
		Ticks:  h.ticks,
		Client: NewHTTPClient(),
		Logger: slog.New(pollSignal{Handler: slog.NewJSONHandler(h.logs, nil), ch: h.polled}),
	}
	h.deps.Write = func(path string, data []byte) error {
		err := WriteAtomic(path, data)
		h.written <- struct{}{}
		return err
	}
	if mutate != nil {
		mutate(h)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.done <- Run(ctx, h.cfg, *h.deps) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-h.done:
			_ = err
		case <-time.After(10 * time.Second):
			t.Error("Run did not stop")
		}
	})
	h.waitWrite()
	return h
}

// waitWrite waits for one poll to finish: the verdict is written and the poll
// line is logged. The write hook fires before the log line, so a test that
// read the logs on the write alone would race with it.
func (h *harness) waitWrite() {
	h.t.Helper()
	for _, ch := range []chan struct{}{h.written, h.polled} {
		select {
		case <-ch:
		case err := <-h.done:
			h.t.Fatalf("Run returned early: %v", err)
		case <-time.After(10 * time.Second):
			h.t.Fatal("a poll did not finish")
		}
	}
}

// pollSignal forwards every record and tells the test when a poll line is logged.
type pollSignal struct {
	slog.Handler
	ch chan struct{}
}

func (p pollSignal) Handle(ctx context.Context, r slog.Record) error {
	err := p.Handler.Handle(ctx, r)
	if r.Message == "poll" {
		select {
		case p.ch <- struct{}{}:
		default:
		}
	}
	return err
}

// tick moves the clock to now+d and runs one poll to completion.
func (h *harness) tick(d time.Duration) verdictDoc {
	h.t.Helper()
	h.clock.Set(t0.Add(d))
	h.ticks <- h.clock.Now()
	h.waitWrite()
	return h.read()
}

func (h *harness) read() verdictDoc {
	h.t.Helper()
	data, err := os.ReadFile(h.out)
	if err != nil {
		h.t.Fatal(err)
	}
	var v verdictDoc
	if err := json.Unmarshal(data, &v); err != nil {
		h.t.Fatalf("verdict file is not valid JSON: %v\n%s", err, data)
	}
	return v
}

func has(rs []string, r string) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}

func TestFirstVerdictIsWrittenAtStartupAndHealthyIsGreen(t *testing.T) {
	h := startHarness(t, nil) // startHarness already waited for the first write: no tick was sent
	v := h.read()
	if v.Overall != "GREEN" || !has(v.Reasons, "watchdog_only") || !v.Watchdog.Seen {
		t.Fatalf("%+v", v)
	}
	if v.TimeSource != "wall" || len(v.Sources) != 1 || v.Sources[0].ID != "alertmanager" || v.Sources[0].State != "ok" || v.Sources[0].AlertCount != 1 {
		t.Fatalf("%+v", v)
	}
	fi, err := os.Stat(h.out)
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v err %v", fi.Mode(), err)
	}
}

func TestRequestShape(t *testing.T) {
	h := startHarness(t, nil)
	h.am.mu.Lock()
	defer h.am.mu.Unlock()
	if h.am.lastPath != "/api/v2/alerts" || h.am.lastQuery != "active=true&silenced=true&inhibited=true&unprocessed=true" || h.am.lastUA != "augur/test" {
		t.Fatalf("path %q query %q ua %q", h.am.lastPath, h.am.lastQuery, h.am.lastUA)
	}
}

func TestClientIgnoresProxyAndRedirects(t *testing.T) {
	c := NewHTTPClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatal("the poll client must have no proxy")
	}
	if c.CheckRedirect == nil {
		t.Fatal("the poll client must not follow redirects")
	}
}

func TestRequestTimeout(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{
		5 * time.Second: 2500 * time.Millisecond, 10 * time.Second: 5 * time.Second,
		20 * time.Second: 10 * time.Second, 30 * time.Second: 10 * time.Second, 60 * time.Second: 10 * time.Second,
	} {
		if got := RequestTimeout(in); got != want {
			t.Errorf("RequestTimeout(%v) = %v, want %v", in, got, want)
		}
	}
}

// Watchdog missing: YELLOW, then RED exactly at the window.
func TestWatchdogMissingThenBlindAtTheWindowEdge(t *testing.T) {
	var noWatchdog atomic.Bool
	h := startHarness(t, nil)
	noWatchdog.Store(true)
	h.am.setBody(func() []string {
		if noWatchdog.Load() {
			return []string{h.am.alert("PeerPrometheusDown", "host-b", "2026-01-15T11:59:00Z", "")}
		}
		return []string{h.am.watchdog(time.Second)}
	})
	cases := []struct {
		at      time.Duration
		overall string
		blind   bool
	}{
		{time.Second, "YELLOW", false},
		{5*time.Minute - time.Nanosecond, "YELLOW", false},
		{5 * time.Minute, "RED", true},
		{5*time.Minute + time.Nanosecond, "RED", true},
	}
	for _, c := range cases {
		v := h.tick(c.at)
		if v.Overall != c.overall || has(v.Reasons, "observability_blind") != c.blind || !has(v.Reasons, "watchdog_missing") || v.Watchdog.Seen {
			t.Fatalf("at %v: %+v", c.at, v)
		}
	}
	// The Watchdog coming back recovers straight away.
	noWatchdog.Store(false)
	if v := h.tick(6 * time.Minute); v.Overall != "GREEN" || has(v.Reasons, "observability_blind") {
		t.Fatalf("recovery: %+v", v)
	}
}

// flaky wraps a real client and fails like a dead server while down is set.
type flaky struct {
	inner Doer
	down  atomic.Bool
}

func (f *flaky) Do(r *http.Request) (*http.Response, error) {
	if f.down.Load() {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	}
	return f.inner.Do(r)
}

// A dead server: YELLOW unreachable with no alerts, RED past the window, then recovery.
func TestUnreachableNeverReusesAlertsThenBlindThenRecovers(t *testing.T) {
	f := &flaky{inner: NewHTTPClient()}
	h := startHarness(t, func(h *harness) { h.deps.Client = f })
	h.am.setBody(func() []string {
		return []string{h.am.watchdog(time.Second), h.am.alert("PeerPrometheusDown", "host-b", "2026-01-15T11:59:00Z", "")}
	})
	if v := h.tick(10 * time.Second); v.Overall != "YELLOW" || len(v.Alerts) != 2 {
		t.Fatalf("healthy with a peer alert: %+v", v)
	}
	f.down.Store(true)
	v := h.tick(20 * time.Second)
	if v.Overall != "YELLOW" || !has(v.Reasons, "alertmanager_unreachable") || !has(v.Reasons, "watchdog_missing") ||
		v.Sources[0].State != "unreachable" || len(v.Alerts) != 0 || v.Watchdog.Seen || v.Sources[0].AlertCount != 0 {
		t.Fatalf("unreachable: %+v", v)
	}
	if v.Sources[0].LastOK == nil || *v.Sources[0].LastOK != "2026-01-15T12:00:10Z" {
		t.Fatalf("last_ok must be the last good poll, got %v", v.Sources[0].LastOK)
	}
	// The clock restarted at the last heartbeat (12:00:10), so the window ends at 12:05:10.
	if v := h.tick(5*time.Minute + 9*time.Second); v.Overall != "YELLOW" {
		t.Fatalf("just inside the window: %+v", v)
	}
	if v := h.tick(5*time.Minute + 10*time.Second); v.Overall != "RED" || !has(v.Reasons, "observability_blind") || !has(v.Reasons, "alertmanager_unreachable") {
		t.Fatalf("at the window: %+v", v)
	}
	f.down.Store(false)
	if v := h.tick(6 * time.Minute); v.Overall != "YELLOW" || v.Sources[0].State != "ok" || len(v.Alerts) != 2 || has(v.Reasons, "observability_blind") {
		t.Fatalf("recovered (peer alert still firing): %+v", v)
	}
}

func TestFailedPollKinds(t *testing.T) {
	big := make([]byte, MaxBody+1)
	for i := range big {
		big[i] = ' '
	}
	tooMany := func() []string {
		out := make([]string, MaxAlerts+1)
		for i := range out {
			out[i] = fmt.Sprintf(`{"labels":{"alertname":"A%d"},"startsAt":"2025-12-01T00:00:00Z","endsAt":"0001-01-01T00:00:00Z","updatedAt":"2026-01-15T12:00:00Z","fingerprint":"f","status":{"state":"active"}}`, i)
		}
		return out
	}
	cases := []struct {
		name    string
		handler func(w http.ResponseWriter, r *http.Request)
		kind    string
	}{
		{"non-200", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) }, KindStatus},
		{"not found", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) }, KindStatus},
		{"body over the cap, chunked", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(big) }, KindTooLarge},
		{"body over the cap, declared", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprint(MaxBody+1))
			_, _ = w.Write(big)
		}, KindTooLarge},
		{"not JSON", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "<html>proxy error</html>") }, KindDecode},
		{"webhook payload", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"version":"4","alerts":[]}`) }, KindDecode},
		{"too many alerts", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "["+strings.Join(tooMany(), ",")+"]")
		}, KindTooMany},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := startHarness(t, nil)
			h.am.set(c.handler)
			v := h.tick(10 * time.Second)
			if v.Overall != "YELLOW" || v.Sources[0].State != "unreachable" || !has(v.Reasons, "alertmanager_unreachable") || len(v.Alerts) != 0 {
				t.Fatalf("%+v", v)
			}
			if !strings.Contains(h.logs.String(), `"error_kind":"`+c.kind+`"`) {
				t.Fatalf("log should name kind %q:\n%s", c.kind, h.logs.String())
			}
		})
	}
}

// A redirect is refused, not followed.
func TestRedirectIsRefused(t *testing.T) {
	var target atomic.Int64
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		target.Add(1)
		_, _ = io.WriteString(w, "[]")
	}))
	defer elsewhere.Close()
	h := startHarness(t, nil)
	h.am.set(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, elsewhere.URL, http.StatusFound) })
	v := h.tick(10 * time.Second)
	if v.Sources[0].State != "unreachable" || target.Load() != 0 {
		t.Fatalf("redirect followed or not refused: hits %d, %+v", target.Load(), v)
	}
	if !strings.Contains(h.logs.String(), `"error_kind":"redirect"`) {
		t.Fatalf("log should name kind redirect:\n%s", h.logs.String())
	}
}

// A request that outlives the timeout is a failed poll.
func TestRequestTimeoutIsAFailedPoll(t *testing.T) {
	release := make(chan struct{})
	h := startHarness(t, func(h *harness) { h.cfg.Timeout = 50 * time.Millisecond })
	h.am.set(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	t.Cleanup(func() { close(release) })
	v := h.tick(10 * time.Second)
	if v.Sources[0].State != "unreachable" || !strings.Contains(h.logs.String(), `"error_kind":"timeout"`) {
		t.Fatalf("%+v\n%s", v, h.logs.String())
	}
}

// Alertmanager is up but the Watchdog's updatedAt is old: stale.
func TestStaleWatchdog(t *testing.T) {
	h := startHarness(t, nil)
	h.am.setBody(func() []string {
		return []string{h.am.watchdog(6 * time.Minute), h.am.alert("PeerPrometheusDown", "host-b", "2026-01-15T11:59:00Z", "")}
	})
	v := h.tick(time.Second)
	if v.Overall != "YELLOW" || v.Sources[0].State != "stale" || !has(v.Reasons, "alertmanager_stale") || !has(v.Reasons, "watchdog_missing") ||
		v.Watchdog.Seen || v.Sources[0].AlertCount != 2 || len(v.Alerts) != 1 {
		t.Fatalf("%+v", v)
	}
	// Exactly the window old is still fresh; one nanosecond past it is stale.
	h.am.setBody(func() []string { return []string{h.am.watchdog(5 * time.Minute)} })
	if v := h.tick(2 * time.Second); v.Sources[0].State != "ok" || !v.Watchdog.Seen {
		t.Fatalf("exactly the window: %+v", v)
	}
	h.am.setBody(func() []string { return []string{h.am.watchdog(5*time.Minute + time.Nanosecond)} })
	if v := h.tick(3 * time.Second); v.Sources[0].State != "stale" {
		t.Fatalf("past the window: %+v", v)
	}
	// Still stale at the dead-man window: RED.
	if v := h.tick(8 * time.Minute); v.Overall != "RED" || !has(v.Reasons, "observability_blind") || !has(v.Reasons, "alertmanager_stale") {
		t.Fatalf("%+v", v)
	}
}

func TestDropStaleWatchdogKeepsOtherAlerts(t *testing.T) {
	now := t0
	old := model.Alert{Name: "Watchdog", Labels: map[string]string{"alertname": "Watchdog"}, UpdatedAt: now.Add(-10 * time.Minute)}
	fresh := model.Alert{Name: "Watchdog", Labels: map[string]string{"alertname": "Watchdog"}, UpdatedAt: now.Add(-time.Minute)}
	other := model.Alert{Name: "X", Labels: map[string]string{"alertname": "X"}, UpdatedAt: now.Add(-time.Hour)}
	w := model.Watchdog{AlertName: "Watchdog", DeadmanWindow: 5 * time.Minute}
	got, stale := DropStaleWatchdog(model.Snapshot{Alerts: []model.Alert{old, other}}, w, now)
	if !stale || len(got.Alerts) != 1 || got.Alerts[0].Name != "X" {
		t.Fatalf("%v %+v", stale, got)
	}
	// A fresh heartbeat next to a stale one: the fresh one stays, and nothing is flagged stale... except the dropped one.
	got, stale = DropStaleWatchdog(model.Snapshot{Alerts: []model.Alert{old, fresh}}, w, now)
	if !stale || len(got.Alerts) != 1 {
		t.Fatalf("%v %+v", stale, got)
	}
	if _, stale = DropStaleWatchdog(model.Snapshot{Alerts: []model.Alert{fresh, other}}, w, now); stale {
		t.Fatal("a fresh heartbeat is not stale")
	}
}

// Logs carry enum values and counts, never label values or alert text.
func TestLogsNeverCarryLabelText(t *testing.T) {
	hostile := "\x1b[31mRED\x1b[0m-" + strings.Repeat("Z", 5000)
	h := startHarness(t, nil)
	h.am.setBody(func() []string {
		return []string{h.am.watchdog(time.Second),
			h.am.alert("PeerPrometheusDown", "host-b", "2026-01-15T11:59:00Z", fmt.Sprintf(`,"note":%q`, hostile))}
	})
	h.tick(time.Second)
	h.am.set(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, hostile, 500) })
	h.tick(2 * time.Second)
	logs := h.logs.String()
	for _, bad := range []string{"\x1b", "ZZZZZZZZ", "PeerPrometheusDown", "host-b", "Watchdog"} {
		if strings.Contains(logs, bad) {
			t.Fatalf("logs contain %q:\n%s", bad, logs)
		}
	}
	if !strings.Contains(logs, `"msg":"poll"`) || !strings.Contains(logs, `"overall"`) || !strings.Contains(logs, `"alert_count"`) ||
		!strings.Contains(logs, `"source_state"`) || !strings.Contains(logs, `"duration_ms"`) {
		t.Fatalf("poll line is missing fields:\n%s", logs)
	}
	if strings.Count(logs, `"msg":"deadman"`) < 2 {
		t.Fatalf("a tracker state change must be logged:\n%s", logs)
	}
}

// SIGHUP is logged and ignored.
func TestHupIsIgnored(t *testing.T) {
	hup := make(chan struct{})
	h := startHarness(t, func(h *harness) { h.deps.Hup = hup })
	hup <- struct{}{}
	h.tick(time.Second) // the loop is alive after the HUP and processed it before the tick
	if !strings.Contains(h.logs.String(), `"msg":"sighup"`) {
		t.Fatalf("no sighup line:\n%s", h.logs.String())
	}
}

// A signal during a write lets the write finish, then Run exits cleanly.
func TestShutdownFinishesTheWriteInProgress(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var first atomic.Bool
	h := startHarness(t, func(h *harness) {
		inner := h.deps.Write
		h.deps.Write = func(path string, data []byte) error {
			if first.CompareAndSwap(false, true) {
				return inner(path, data) // the startup write goes straight through
			}
			close(entered)
			<-release
			return inner(path, data)
		}
	})
	h.clock.Set(t0.Add(time.Second))
	h.ticks <- h.clock.Now()
	<-entered
	h.cancel() // SIGTERM while the write is in progress
	close(release)
	select {
	case err := <-h.done:
		if err != nil {
			t.Fatalf("Run = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
	h.waitWrite() // the in-progress write completed
	if v := h.read(); v.Overall != "GREEN" {
		t.Fatalf("%+v", v)
	}
	h.done <- nil // let the cleanup receive
}

// A shutdown during the fetch is not a failed poll: nothing is written.
func TestShutdownDuringFetchWritesNothing(t *testing.T) {
	h := startHarness(t, nil)
	before, err := os.ReadFile(h.out)
	if err != nil {
		t.Fatal(err)
	}
	inFlight := make(chan struct{})
	h.am.set(func(_ http.ResponseWriter, r *http.Request) {
		close(inFlight)
		<-r.Context().Done()
	})
	h.clock.Set(t0.Add(time.Second))
	h.ticks <- h.clock.Now()
	<-inFlight
	h.cancel()
	if err := <-h.done; err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(h.out)
	if !bytes.Equal(before, after) {
		t.Fatal("a shutdown must not overwrite the file with a failed-poll verdict")
	}
	h.done <- nil
}

// An oversized verdict is an internal error and the last file is left alone.
func TestOversizedVerdictStopsWithoutWriting(t *testing.T) {
	old := verdictLimit
	defer func() { verdictLimit = old }()
	h := startHarness(t, nil)
	before, _ := os.ReadFile(h.out)
	verdictLimit = 100 // set while Run is idle, before the next tick
	h.clock.Set(t0.Add(time.Second))
	h.ticks <- h.clock.Now()
	select {
	case err := <-h.done:
		if !errors.Is(err, ErrVerdictTooLarge) {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
	after, _ := os.ReadFile(h.out)
	if !bytes.Equal(before, after) {
		t.Fatal("the last file must be left alone")
	}
	h.done <- nil
}

// A write failure does not stop the loop: the file ages into stale and the next poll retries.
func TestWriteFailureIsLoggedAndRetried(t *testing.T) {
	var fail atomic.Bool
	h := startHarness(t, func(h *harness) {
		inner := h.deps.Write
		h.deps.Write = func(path string, data []byte) error {
			if fail.Load() {
				h.written <- struct{}{}
				return errors.New("disk full")
			}
			return inner(path, data)
		}
	})
	fail.Store(true)
	h.tick(time.Second)
	if !strings.Contains(h.logs.String(), `"write":"failed"`) {
		t.Fatalf("%s", h.logs.String())
	}
	fail.Store(false)
	if v := h.tick(2 * time.Second); v.Overall != "GREEN" {
		t.Fatalf("%+v", v)
	}
}

func TestNoTickerIsAnError(t *testing.T) {
	if err := Run(context.Background(), Config{}, Deps{}); err == nil {
		t.Fatal("Run without a ticker must fail")
	}
}
