package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Hedronite/augur/internal/decode"
	"github.com/Hedronite/augur/internal/engine"
	"github.com/Hedronite/augur/internal/model"
	"github.com/Hedronite/augur/internal/policy"
	"github.com/Hedronite/augur/internal/render"
)

// maxInputBytes caps every input file. A file that cannot be read, or is over
// the cap, is an input error (exit 3) for --alerts and a config error (exit 5)
// for --policy. Exit 4 means the policy was read but is invalid.
const maxInputBytes = 16 << 20

// wallClock is the process clock. It is a variable so tests can fix it; the
// engine never reads it, it only receives the value.
var wallClock = time.Now

// readCapped reads the file at path and fails if it is larger than limit.
func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // the path is the operator's own flag value
	if err != nil {
		return nil, unwrapPathError(err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, unwrapPathError(err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file is larger than %d MiB", limit>>20)
	}
	return data, nil
}

func unwrapPathError(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// loadPolicy reads and parses a policy file. On a policy problem it writes
// every problem to stderr and returns an exit error with no further message.
func loadPolicy(path string, stderr io.Writer) (model.Policy, error) {
	data, err := readCapped(path, maxInputBytes)
	if err != nil {
		return model.Policy{}, &exitError{code: ExitConfig, msg: fmt.Sprintf("cannot read policy %s: %v", path, err)}
	}
	pol, errs := policy.Parse(data)
	if len(errs) > 0 {
		_, _ = fmt.Fprintf(stderr, "augur: invalid_policy: %d problem(s) in %s\n", len(errs), path)
		if rerr := render.Errors(stderr, path, errs); rerr != nil {
			return model.Policy{}, &exitError{code: ExitInternal, msg: fmt.Sprintf("cannot write the policy errors: %v", rerr)}
		}
		return model.Policy{}, &exitError{code: ExitPolicy}
	}
	return pol, nil
}

func loadAlerts(path string) (model.Snapshot, error) {
	data, err := readCapped(path, maxInputBytes)
	if err != nil {
		return model.Snapshot{}, &exitError{code: ExitInput, msg: fmt.Sprintf("invalid_input: cannot read alerts %s: %v", path, err)}
	}
	kind, err := decode.Sniff(data)
	if err != nil {
		return model.Snapshot{}, decodeError(path, err)
	}
	switch kind {
	case decode.KindAMv2:
	case decode.KindAMWebhookV4, decode.KindGrafana:
		return model.Snapshot{}, decodeError(path, &decode.ErrUnsupported{Kind: kind})
	default:
		return model.Snapshot{}, decodeError(path, &decode.ErrMalformed{Detail: "not an Alertmanager v2 alerts array"})
	}
	snap, err := decode.DecodeAM(data)
	if err != nil {
		return model.Snapshot{}, decodeError(path, err)
	}
	return snap, nil
}

// decodeError turns a decoder error into an input exit error that names the
// code and says how to fix it.
func decodeError(path string, err error) error {
	var unsup *decode.ErrUnsupported
	var bad *decode.ErrMalformed
	switch {
	case errors.As(err, &unsup):
		return &exitError{code: ExitInput, msg: fmt.Sprintf(
			"unsupported_payload: %s in %s\nAugur reads the Alertmanager v2 API response (GET /api/v2/alerts); save that response and pass it as --alerts.",
			unsup.Kind, path)}
	case errors.As(err, &bad):
		return &exitError{code: ExitInput, msg: fmt.Sprintf(
			"invalid_input: %s in %s\nPass the unmodified JSON array from GET /api/v2/alerts as --alerts.",
			bad.Detail, path)}
	default:
		return &exitError{code: ExitInput, msg: fmt.Sprintf("invalid_input: cannot decode %s", path)}
	}
}

func severityExit(s model.Severity) int {
	switch s {
	case model.Green:
		return ExitGreen
	case model.Yellow:
		return ExitYellow
	case model.Red:
		return ExitRed
	default:
		return ExitInternal
	}
}

func parseNow(flag string) (time.Time, string, error) {
	if flag == "" {
		return wallClock().UTC(), model.TimeWall, nil
	}
	t, err := time.Parse(time.RFC3339, flag)
	if err != nil {
		return time.Time{}, "", &exitError{code: ExitConfig, msg: "invalid --now: expected an RFC3339 time such as 2026-01-15T12:00:00Z"}
	}
	return t.UTC(), model.TimeFlag, nil
}

func runEvaluate(cmd *cobra.Command, alertsPath, policyPath, nowFlag string, asJSON, quiet bool) error {
	now, source, err := parseNow(nowFlag)
	if err != nil {
		return err
	}
	pol, err := loadPolicy(policyPath, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	snap, err := loadAlerts(alertsPath)
	if err != nil {
		return err
	}
	snap.SourceID = "file"
	snap.State = model.SourceOK
	ok := now
	snap.LastOK = &ok

	v := engine.Evaluate(snap, pol, now)
	v.TimeSource = source

	if !quiet {
		var werr error
		if asJSON {
			werr = render.JSON(cmd.OutOrStdout(), v)
		} else {
			werr = render.Human(cmd.OutOrStdout(), v)
		}
		if werr != nil {
			return &exitError{code: ExitInternal, msg: fmt.Sprintf("cannot write the verdict: %v", werr)}
		}
	}
	return &exitError{code: severityExit(v.Overall)}
}

func runValidate(cmd *cobra.Command, policyPath string, quiet bool) error {
	if _, err := loadPolicy(policyPath, cmd.ErrOrStderr()); err != nil {
		return err
	}
	if !quiet {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "ok: %s\n", policyPath)
	}
	return nil
}
