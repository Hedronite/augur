package serve

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path/filepath"
	"sort"
	"time"

	"github.com/Hedronite/augur/internal/deadman"
	"github.com/Hedronite/augur/internal/engine"
	"github.com/Hedronite/augur/internal/model"
	"github.com/Hedronite/augur/internal/render"
)

// SourceID names the Alertmanager source in the verdict.
const SourceID = "alertmanager"

// Config is what serve needs from the command line and the policy.
type Config struct {
	Policy   model.Policy
	URL      *url.URL
	Out      string
	Interval time.Duration
	Version  string
	// Timeout overrides the per-request timeout; zero means
	// RequestTimeout(Interval). Tests use it to avoid real waits.
	Timeout time.Duration
}

// Deps are the injected effects. Zero values get production defaults in Run,
// except Ticks, which the caller owns (a nil Ticks is an error).
type Deps struct {
	Now    func() time.Time
	Ticks  <-chan time.Time
	Client Doer
	Write  func(path string, data []byte) error
	Logger *slog.Logger
	// Hup delivers SIGHUP; it is logged and ignored (no policy reload in v0).
	Hup <-chan struct{}
}

// verdictLimit is MaxVerdictBytes; a variable so a test can lower it.
var verdictLimit = MaxVerdictBytes

// ErrVerdictTooLarge means the rendered verdict exceeds the reader's cap. It is
// an internal error: the verdict is never truncated, because a partial verdict
// could hide a RED, so the last file is left to go stale.
var ErrVerdictTooLarge = errors.New("verdict is larger than the 4 MiB reader cap")

// Run polls until ctx is cancelled and returns nil on a clean shutdown. The
// first verdict is written immediately. It returns an error only for an
// internal failure (an oversized verdict); the last file is left alone then.
func Run(ctx context.Context, cfg Config, d Deps) error {
	if d.Ticks == nil {
		return errors.New("serve: no ticker")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Client == nil {
		d.Client = NewHTTPClient()
	}
	if d.Write == nil {
		d.Write = WriteAtomic
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}

	s := &server{cfg: cfg, d: d}
	s.start = d.Now()
	s.tracker = deadman.New(cfg.Policy.Watchdog.DeadmanWindow, s.start)
	s.target = AlertsURL(cfg.URL)
	s.timeout = RequestTimeout(cfg.Interval)
	if cfg.Timeout > 0 {
		s.timeout = cfg.Timeout
	}
	s.userAgent = "augur/" + cfg.Version

	if removed, err := CleanStrayTemp(filepath.Dir(cfg.Out)); err != nil {
		d.Logger.Warn("cleanup", "kind", "cannot_list_directory")
	} else if removed > 0 {
		d.Logger.Info("cleanup", "removed_temp_files", removed)
	}
	d.Logger.Info("start", "interval_ms", cfg.Interval.Milliseconds(), "version", cfg.Version)

	if err := s.poll(ctx); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			d.Logger.Info("stop", "reason", "signal")
			return nil
		case <-d.Hup:
			d.Logger.Info("sighup", "action", "ignored", "note", "restart to reload the policy")
		case <-d.Ticks:
			// A cancelled context wins over a tick that arrived with it.
			if ctx.Err() != nil {
				d.Logger.Info("stop", "reason", "signal")
				return nil
			}
			if err := s.poll(ctx); err != nil {
				return err
			}
		}
	}
}

type server struct {
	cfg       Config
	d         Deps
	start     time.Time
	tracker   *deadman.Tracker
	target    string
	timeout   time.Duration
	userAgent string

	lastOK   *time.Time
	lastDead deadman.State
	haveDead bool
}

// poll runs one cycle: fetch, classify, run the tracker, write. A cancelled
// context during the fetch is a shutdown, not a failed poll: nothing is written.
func (s *server) poll(ctx context.Context) error {
	began := s.d.Now()
	snap, ferr := fetch(ctx, s.d.Client, s.target, s.timeout, s.userAgent)

	var pe *PollError
	failKind := ""
	if ferr != nil {
		if errors.As(ferr, &pe) {
			failKind = pe.Kind
		} else {
			failKind = KindConnect
		}
		if failKind == KindCanceled {
			return nil
		}
	}

	now := s.d.Now().UTC()
	v := s.verdict(snap, failKind, now)
	data, err := renderBytes(v)
	if err != nil {
		s.d.Logger.Error("render", "kind", "render_failed")
		return fmt.Errorf("render verdict: %w", err)
	}
	if len(data) > verdictLimit {
		s.d.Logger.Error("verdict_too_large", "bytes", len(data), "limit", verdictLimit)
		return ErrVerdictTooLarge
	}

	// Once the file is being replaced, finish it whatever the context says.
	werr := s.d.Write(s.cfg.Out, data)
	attrs := []any{
		"overall", string(v.Overall),
		"alert_count", v.Sources[0].AlertCount,
		"source_state", string(v.Sources[0].State),
		"duration_ms", s.d.Now().Sub(began).Milliseconds(),
	}
	if failKind != "" {
		attrs = append(attrs, "error_kind", failKind)
	}
	if werr != nil {
		attrs = append(attrs, "write", "failed")
		s.d.Logger.Error("poll", attrs...)
		return nil // the file ages into stale; the next poll tries again
	}
	s.d.Logger.Info("poll", attrs...)
	return nil
}

// verdict builds the verdict for one poll.
func (s *server) verdict(snap model.Snapshot, failKind string, now time.Time) model.Verdict {
	pol := s.cfg.Policy
	if failKind != "" {
		// A failed poll never reuses an earlier snapshot's alerts.
		snap = model.Snapshot{Alerts: nil}
		snap.State = model.SourceUnreachable
		snap.LastOK = s.lastOK
	} else {
		snap.State = model.SourceOK
		snap.LastOK = &now
		s.lastOK = &now
	}
	snap.SourceID = SourceID

	total := len(snap.Alerts)
	if failKind == "" {
		var stale bool
		snap, stale = DropStaleWatchdog(snap, pol.Watchdog, now)
		if stale {
			snap.State = model.SourceStale
		}
	}

	v := engine.Evaluate(snap, pol, now)
	v.TimeSource = model.TimeWall
	v.Sources[0].AlertCount = total // the count read, not the count kept

	sourceOK := failKind == ""
	st := s.tracker.Observe(now, v.Watchdog.Seen, sourceOK)
	s.logTracker(st)
	return MergeDeadman(v, st)
}

func (s *server) logTracker(st deadman.State) {
	if s.haveDead && st.Severity == s.lastDead.Severity && equalReasons(st.Reasons, s.lastDead.Reasons) {
		return
	}
	s.lastDead, s.haveDead = st, true
	rs := make([]string, len(st.Reasons))
	for i, r := range st.Reasons {
		rs[i] = string(r)
	}
	s.d.Logger.Info("deadman", "severity", string(st.Severity), "reasons", rs)
}

func equalReasons(a, b []model.Reason) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// DropStaleWatchdog removes heartbeat alerts whose updatedAt is older than the
// dead-man window, so the engine sees no heartbeat: Alertmanager is up but
// Prometheus has stopped refreshing it. It reports whether it dropped any, and
// leaves every other alert alone. The engine stays pure; this is the
// serve-side check.
func DropStaleWatchdog(snap model.Snapshot, w model.Watchdog, now time.Time) (model.Snapshot, bool) {
	if w.AlertName == "" {
		return snap, false
	}
	kept := make([]model.Alert, 0, len(snap.Alerts))
	stale := false
	for _, a := range snap.Alerts {
		if a.Labels["alertname"] == w.AlertName && now.Sub(a.UpdatedAt) > w.DeadmanWindow {
			stale = true
			continue
		}
		kept = append(kept, a)
	}
	if !stale {
		return snap, false
	}
	snap.Alerts = kept
	return snap, true
}

// MergeDeadman folds the tracker's state into the engine's verdict: overall is
// the worse of the two, and the tracker's rollup reasons are added.
func MergeDeadman(v model.Verdict, st deadman.State) model.Verdict {
	v.Overall = model.Worse(v.Overall, st.Severity)
	set := make(map[model.Reason]bool, len(v.Reasons)+len(st.Reasons))
	for _, r := range v.Reasons {
		set[r] = true
	}
	for _, r := range st.Reasons {
		set[r] = true
	}
	if v.Overall != model.Green {
		delete(set, model.ReasonWatchdogOnly)
	}
	out := make([]model.Reason, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	v.Reasons = out
	return v
}

func renderBytes(v model.Verdict) ([]byte, error) {
	var buf bytes.Buffer
	if err := render.JSON(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
