// Package engine classifies a snapshot against a policy. It is pure: no I/O,
// no goroutines and no clock; "now" is an argument.
package engine

import (
	"time"

	"github.com/Hedronite/augur/internal/model"
)

// Evaluate classifies snap against pol as of now. The returned Verdict has
// TimeSource unset (the caller knows where now came from) and every slice
// sorted and non-nil.
func Evaluate(snap model.Snapshot, pol model.Policy, now time.Time) model.Verdict {
	_, _, _ = snap, pol, now
	return model.Verdict{Schema: model.VerdictSchema}
}
