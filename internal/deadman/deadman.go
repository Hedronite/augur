// Package deadman is the dead-man state machine behind serve's
// observability_blind. It is a pure type: no goroutines, no timers and no
// clock reads; every observation carries its own time.
package deadman

import (
	"time"

	"github.com/Hedronite/augur/internal/model"
)

// State is the result of one observation.
type State struct {
	Severity model.Severity
	Reasons  []model.Reason // sorted
}

// Tracker follows the heartbeat across observations.
type Tracker struct {
	window time.Duration
	start  time.Time
}

// New returns a Tracker whose blind window is window and whose clock starts
// at start. There is no state file: a restart resets it.
func New(window time.Duration, start time.Time) *Tracker {
	return &Tracker{window: window, start: start}
}

// Observe records one poll and returns the resulting state.
func (t *Tracker) Observe(now time.Time, watchdogSeen, sourceOK bool) State {
	_, _, _ = now, watchdogSeen, sourceOK
	return State{Severity: model.Red}
}
