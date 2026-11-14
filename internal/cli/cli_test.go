package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Execute(args, &out, &errb)
	return code, out.String(), errb.String()
}

// The exit codes are a public contract; changing one is a breaking change.
func TestExitCodesAreFrozen(t *testing.T) {
	want := map[string]int{
		"green": 0, "yellow": 1, "red": 2, "input": 3, "policy": 4, "config": 5, "internal": 6,
	}
	got := map[string]int{
		"green": ExitGreen, "yellow": ExitYellow, "red": ExitRed,
		"input": ExitInput, "policy": ExitPolicy, "config": ExitConfig, "internal": ExitInternal,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("exit code %s = %d, want %d", k, got[k], v)
		}
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := run(t, "version")
	if code != 0 || !strings.HasPrefix(out, "augur ") {
		t.Fatalf("version: code %d, stdout %q", code, out)
	}
}

// serve is still a stub (A2): it must exit 6, never a verdict.
func TestStubsExitInternalNotGreen(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"serve", []string{"serve", "--policy", "p.yaml", "--alertmanager", "http://127.0.0.1:9093", "--out", "v.json"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errs := run(t, tc.args...)
			if code != ExitInternal {
				t.Errorf("exit = %d, want %d", code, ExitInternal)
			}
			if out != "" {
				t.Errorf("stdout must stay empty when there is no verdict, got %q", out)
			}
			if !strings.Contains(errs, "not implemented") {
				t.Errorf("stderr %q should say not implemented", errs)
			}
		})
	}
}

func TestUsageErrorsExitConfig(t *testing.T) {
	cases := [][]string{
		{"nosuchcommand"},
		{"evaluate", "--policy", "p.yaml"},                                  // missing --alerts
		{"evaluate", "--alerts", "a", "--policy", "p", "--bogus"},           // unknown flag
		{"evaluate", "--alerts", "a", "--policy", "p", "--json", "--quiet"}, // exclusive
	}
	for _, args := range cases {
		code, out, errs := run(t, args...)
		if code != ExitConfig {
			t.Errorf("%v: exit = %d, want %d (stderr %q)", args, code, ExitConfig, errs)
		}
		if out != "" {
			t.Errorf("%v: stdout %q, want empty", args, out)
		}
	}
}

// A bare invocation has no verdict, so it must not exit 0 (GREEN). --help may.
func TestBareInvocationIsNotGreen(t *testing.T) {
	code, out, errs := run(t)
	if code != ExitConfig {
		t.Errorf("bare augur: exit = %d, want %d (stderr %q)", code, ExitConfig, errs)
	}
	if out != "" {
		t.Errorf("bare augur: stdout %q, want empty", out)
	}
	if code, _, _ := run(t, "--help"); code != 0 {
		t.Errorf("--help: exit = %d, want 0", code)
	}
}

// A panic must never surface as exit 2, which would read as RED.
func TestPanicExitsInternal(t *testing.T) {
	root := &cobra.Command{Use: "augur", RunE: func(*cobra.Command, []string) error { panic("boom") }}
	var out, errb bytes.Buffer
	code := execute(root, nil, &out, &errb)
	if code != ExitInternal {
		t.Fatalf("panic exit = %d, want %d", code, ExitInternal)
	}
	if !strings.Contains(errb.String(), "internal error") {
		t.Errorf("stderr %q should mention internal error", errb.String())
	}
}
