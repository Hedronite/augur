// Package deadman is the dead-man state machine behind serve's
// observability_blind. It is a pure type: no goroutines, no timers and no
// clock reads; every observation carries its own time.
package deadman

import (
	"sort"
	"time"

	"github.com/Hedronite/augur/internal/model"
)

// State is the result of one observation. Reasons are the rollup codes only
// (watchdog_missing, observability_blind, source_unreachable, clock_skew); the
// per-alert heartbeat reason belongs to the engine. A Severity of GREEN means
// "GREEN-eligible": the heartbeat is current, and the alerts decide the rest.
type State struct {
	Severity model.Severity
	Reasons  []model.Reason // sorted
}

// Tracker follows the heartbeat across observations. The zero value is not
// usable; call New.
type Tracker struct {
	window   time.Duration
	clock    time.Time // max(start, last seen heartbeat)
	lastSeen time.Time // zero until a heartbeat is seen
	lastObs  time.Time // latest observation time so far
	observed bool
}

// New returns a Tracker whose blind window is window and whose clock starts
// at start. There is no state file: a restart resets it.
func New(window time.Duration, start time.Time) *Tracker {
	return &Tracker{window: window, clock: start}
}

// Observe records one poll and returns the resulting state.
//
//   - watchdogSeen && sourceOK: the heartbeat is current; the clock restarts
//     at now and the state is GREEN-eligible. Recovery is immediate.
//   - otherwise (not seen, or the source unreachable): YELLOW watchdog_missing
//     while less than the window has passed since the clock, RED
//     observability_blind once the window or more has passed. An unreachable
//     source also reports source_unreachable.
//   - a now earlier than the previous observation never moves the state
//     backwards: it is treated as the previous observation time (zero elapsed
//     time) and reports clock_skew.
func (t *Tracker) Observe(now time.Time, watchdogSeen, sourceOK bool) State {
	var reasons []model.Reason

	if t.observed && now.Before(t.lastObs) {
		now = t.lastObs
		reasons = append(reasons, model.ReasonClockSkew)
	}
	t.lastObs = now
	t.observed = true

	if watchdogSeen && sourceOK {
		t.lastSeen = now
		if now.After(t.clock) {
			t.clock = now
		}
		return State{Severity: model.Green, Reasons: sorted(reasons)}
	}

	if !sourceOK {
		reasons = append(reasons, model.ReasonSourceUnreachable)
	}
	elapsed := now.Sub(t.clock)
	if elapsed < 0 {
		elapsed = 0
	}
	if elapsed >= t.window {
		reasons = append(reasons, model.ReasonObservabilityBlind)
		return State{Severity: model.Red, Reasons: sorted(reasons)}
	}
	reasons = append(reasons, model.ReasonWatchdogMissing)
	return State{Severity: model.Yellow, Reasons: sorted(reasons)}
}

func sorted(rs []model.Reason) []model.Reason {
	out := append([]model.Reason{}, rs...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
