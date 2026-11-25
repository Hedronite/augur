package serve

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"slices"
	"time"

	"github.com/Hedronite/augur/internal/model"
)

// priorVerdict is the part of the last verdict file a new run reads. There is
// no state file: the verdict is the only thing serve leaves behind.
type priorVerdict struct {
	APIVersion  string         `json:"apiVersion"`
	GeneratedAt time.Time      `json:"generated_at"`
	TimeSource  string         `json:"time_source"`
	Reasons     []model.Reason `json:"reasons"`
	Watchdog    struct {
		Seen         bool       `json:"seen"`
		DeadmanSince *time.Time `json:"deadman_since"`
	} `json:"watchdog"`
	Sources []struct {
		ID     string            `json:"id"`
		State  model.SourceState `json:"state"`
		LastOK *time.Time        `json:"last_ok"`
	} `json:"sources"`
}

var errNotServeVerdict = errors.New("not a verdict written by serve")

// resumeDeadman seeds the tracker from the last verdict at --out. A missing,
// unreadable or foreign file is not an error: the window then starts now, as
// on a first run. The log names the outcome only, never the file's content.
func (s *server) resumeDeadman() {
	data, err := readPrior(s.cfg.Out)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	var since time.Time
	if err == nil {
		since, err = deadmanSince(data, s.cfg.Policy.Watchdog.DeadmanWindow, s.start)
	}
	if err != nil {
		s.d.Logger.Warn("resume", "kind", "unusable_verdict")
		return
	}
	s.tracker.Resume(since)
	s.d.Logger.Info("resume", "kind", "restored", "elapsed_ms", s.start.Sub(since).Milliseconds())
}

// readPrior reads a regular file no larger than the verdict cap.
func readPrior(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	// Checked before opening: opening a pipe would block the start.
	if !fi.Mode().IsRegular() {
		return nil, errNotServeVerdict
	}
	f, err := os.Open(path) //nolint:gosec // the operator's own --out
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, MaxVerdictBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxVerdictBytes {
		return nil, errNotServeVerdict
	}
	return data, nil
}

// deadmanSince returns the instant a new run's dead-man window counts from,
// given the last verdict. It is never later than start, and a verdict that was
// already blind stays blind until a heartbeat is seen.
func deadmanSince(data []byte, window time.Duration, start time.Time) (time.Time, error) {
	var p priorVerdict
	if err := json.Unmarshal(data, &p); err != nil {
		return time.Time{}, err
	}
	if p.APIVersion != model.VerdictAPIVersion || p.TimeSource != model.TimeWall || p.GeneratedAt.IsZero() ||
		len(p.Sources) != 1 || p.Sources[0].ID != SourceID {
		return time.Time{}, errNotServeVerdict
	}
	src := p.Sources[0]

	// A current heartbeat restarted the window when the verdict was made.
	since := p.GeneratedAt
	switch {
	case p.Watchdog.DeadmanSince != nil:
		since = *p.Watchdog.DeadmanSince
	case !p.Watchdog.Seen && src.State == model.SourceUnreachable && src.LastOK != nil:
		// A verdict from before deadman_since existed: the last good poll is
		// the closest thing to the last heartbeat it records.
		since = *src.LastOK
	}
	if since.After(start) {
		since = start
	}
	if slices.Contains(p.Reasons, model.ReasonObservabilityBlind) {
		if latest := start.Add(-window); since.After(latest) {
			since = latest
		}
	}
	return since, nil
}
