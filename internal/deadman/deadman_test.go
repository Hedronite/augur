package deadman_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/Hedronite/augur/internal/deadman"
	"github.com/Hedronite/augur/internal/model"
)

var t0 = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

const window = 5 * time.Minute

func rs(r ...model.Reason) []model.Reason { return append([]model.Reason{}, r...) }

func TestWindowEdge(t *testing.T) {
	cases := []struct {
		name    string
		elapsed time.Duration
		want    deadman.State
	}{
		{"zero", 0, deadman.State{Severity: model.Yellow, Reasons: rs(model.ReasonWatchdogMissing)}},
		{"window-1ns", window - 1, deadman.State{Severity: model.Yellow, Reasons: rs(model.ReasonWatchdogMissing)}},
		{"window", window, deadman.State{Severity: model.Red, Reasons: rs(model.ReasonObservabilityBlind)}},
		{"window+1ns", window + 1, deadman.State{Severity: model.Red, Reasons: rs(model.ReasonObservabilityBlind)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := deadman.New(window, t0)
			got := tr.Observe(t0.Add(c.elapsed), false, true)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestSeenIsGreenEligibleAndRestartsClock(t *testing.T) {
	tr := deadman.New(window, t0)
	if got := tr.Observe(t0.Add(time.Minute), true, true); got.Severity != model.Green || len(got.Reasons) != 0 {
		t.Fatalf("seen: %+v", got)
	}
	// The clock restarted at the heartbeat, so 4m59s later is still YELLOW.
	if got := tr.Observe(t0.Add(time.Minute+window-time.Second), false, true); got.Severity != model.Yellow {
		t.Fatalf("after heartbeat, within window: %+v", got)
	}
	if got := tr.Observe(t0.Add(time.Minute+window), false, true); got.Severity != model.Red {
		t.Fatalf("after heartbeat, at window: %+v", got)
	}
}

func TestRecoveryIsImmediate(t *testing.T) {
	tr := deadman.New(window, t0)
	if got := tr.Observe(t0.Add(10*time.Minute), false, true); got.Severity != model.Red {
		t.Fatalf("blind: %+v", got)
	}
	got := tr.Observe(t0.Add(10*time.Minute+time.Second), true, true)
	if got.Severity != model.Green || len(got.Reasons) != 0 {
		t.Fatalf("recovery: %+v", got)
	}
}

func TestUnreachableSource(t *testing.T) {
	tr := deadman.New(window, t0)
	// A heartbeat flag is ignored when the source is not ok.
	got := tr.Observe(t0.Add(time.Minute), true, false)
	want := deadman.State{Severity: model.Yellow, Reasons: rs(model.ReasonSourceUnreachable, model.ReasonWatchdogMissing)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	got = tr.Observe(t0.Add(window), false, false)
	want = deadman.State{Severity: model.Red, Reasons: rs(model.ReasonObservabilityBlind, model.ReasonSourceUnreachable)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestBackwardsTimeNeverMovesStateBack(t *testing.T) {
	tr := deadman.New(window, t0)
	if got := tr.Observe(t0.Add(window), false, true); got.Severity != model.Red {
		t.Fatalf("blind: %+v", got)
	}
	// An earlier now must not read as less elapsed time.
	got := tr.Observe(t0.Add(time.Minute), false, true)
	want := deadman.State{Severity: model.Red, Reasons: rs(model.ReasonClockSkew, model.ReasonObservabilityBlind)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestBackwardsHeartbeatDoesNotRewindClock(t *testing.T) {
	tr := deadman.New(window, t0)
	tr.Observe(t0.Add(3*time.Minute), true, true)
	got := tr.Observe(t0.Add(time.Minute), true, true)
	if got.Severity != model.Green || !reflect.DeepEqual(got.Reasons, rs(model.ReasonClockSkew)) {
		t.Fatalf("got %+v", got)
	}
	// The clock is still 3m (the later heartbeat), so 3m+window-1ns is YELLOW.
	if got := tr.Observe(t0.Add(3*time.Minute+window-1), false, true); got.Severity != model.Yellow {
		t.Fatalf("got %+v", got)
	}
}

func TestClockStartsAtMaxOfStartAndLastSeen(t *testing.T) {
	// start later than now: elapsed is clamped at zero, not negative.
	tr := deadman.New(window, t0.Add(time.Hour))
	if got := tr.Observe(t0, false, true); got.Severity != model.Yellow {
		t.Fatalf("got %+v", got)
	}
}
