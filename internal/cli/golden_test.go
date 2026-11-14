package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixtureRoot = "../../testdata/fixtures"

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixtureDirs(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	if len(dirs) == 0 {
		t.Fatal("no fixtures found")
	}
	return dirs
}

func overallExit(t *testing.T, verdict []byte) int {
	t.Helper()
	var v struct {
		Overall string `json:"overall"`
	}
	if err := json.Unmarshal(verdict, &v); err != nil {
		t.Fatal(err)
	}
	switch v.Overall {
	case "GREEN":
		return ExitGreen
	case "YELLOW":
		return ExitYellow
	case "RED":
		return ExitRed
	}
	t.Fatalf("overall %q", v.Overall)
	return -1
}

// TestGoldenFixtures runs every fixture through the real CLI path (decode,
// policy, engine, render) and compares the exit code and the canonical JSON
// byte for byte. The fixtures are the spec: if this fails, the code is wrong.
func TestGoldenFixtures(t *testing.T) {
	for _, name := range fixtureDirs(t) {
		dir := filepath.Join(fixtureRoot, name)
		t.Run(name, func(t *testing.T) {
			now := strings.TrimSpace(string(readFile(t, filepath.Join(dir, "now.txt"))))
			alerts := filepath.Join(dir, "alerts.json")
			policy := filepath.Join(dir, "policy.yaml")
			eval := []string{"evaluate", "--alerts", alerts, "--policy", policy, "--now", now}

			if want, err := os.ReadFile(filepath.Join(dir, "expected.json")); err == nil {
				code, out, errs := run(t, append(eval, "--json")...)
				if wc := overallExit(t, want); code != wc {
					t.Errorf("exit = %d, want %d (stderr %q)", code, wc, errs)
				}
				if errs != "" {
					t.Errorf("stderr must be empty on a verdict, got %q", errs)
				}
				if out != string(want) {
					t.Errorf("canonical JSON differs from expected.json\n got: %s\nwant: %s", out, want)
				}
				// Human and quiet modes agree on the exit code.
				if hc, hout, _ := run(t, eval...); hc != code || hout == "" {
					t.Errorf("human mode: exit %d (want %d), stdout length %d", hc, code, len(hout))
				}
				if qc, qout, _ := run(t, append(eval, "--quiet")...); qc != code || qout != "" {
					t.Errorf("quiet mode: exit %d (want %d), stdout %q", qc, code, qout)
				}
				if vc, vout, verrs := run(t, "validate", "--policy", policy); vc != 0 || vout == "" {
					t.Errorf("validate: exit %d, stdout %q, stderr %q", vc, vout, verrs)
				}
				return
			}

			var want struct {
				Exit   int    `json:"exit"`
				Code   string `json:"code"`
				Detail string `json:"detail"`
			}
			if err := json.Unmarshal(readFile(t, filepath.Join(dir, "expected_error.json")), &want); err != nil {
				t.Fatal(err)
			}
			code, out, errs := run(t, append(eval, "--json")...)
			if code != want.Exit {
				t.Errorf("exit = %d, want %d (stderr %q)", code, want.Exit, errs)
			}
			if out != "" {
				t.Errorf("stdout must be empty when there is no verdict, got %q", out)
			}
			if !strings.Contains(errs, want.Code) {
				t.Errorf("stderr should name %q, got %q", want.Code, errs)
			}
			switch want.Exit {
			case ExitInput:
				if want.Code == "unsupported_payload" && !strings.Contains(errs, want.Detail) {
					t.Errorf("stderr should name %q, got %q", want.Detail, errs)
				}
			case ExitPolicy:
				// validate reports every listed field path, not just the first.
				vc, vout, verrs := run(t, "validate", "--policy", policy)
				if vc != ExitPolicy || vout != "" {
					t.Errorf("validate: exit %d, stdout %q", vc, vout)
				}
				for _, path := range strings.Split(want.Detail, ",") {
					if !strings.Contains(verrs, path) {
						t.Errorf("validate stderr should name field %q, got %q", path, verrs)
					}
					if !strings.Contains(errs, path) {
						t.Errorf("evaluate stderr should name field %q, got %q", path, errs)
					}
				}
			}
		})
	}
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const goodPolicyFixture = "50-node-exporter-past-hold-single-view"

func goodArgs(t *testing.T) (alerts, policy string) {
	t.Helper()
	dir := filepath.Join(fixtureRoot, goodPolicyFixture)
	return filepath.Join(dir, "alerts.json"), filepath.Join(dir, "policy.yaml")
}

// Without --now the wall clock is used, and the verdict says so.
func TestWallClockWhenNoNow(t *testing.T) {
	alerts, policy := goodArgs(t)
	fixed := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	old := wallClock
	wallClock = func() time.Time { return fixed }
	defer func() { wallClock = old }()

	_, out, _ := run(t, "evaluate", "--alerts", alerts, "--policy", policy, "--json")
	var v struct {
		GeneratedAt string `json:"generated_at"`
		TimeSource  string `json:"time_source"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("%v: %q", err, out)
	}
	if v.TimeSource != "wall" || v.GeneratedAt != "2026-01-15T12:00:00Z" {
		t.Fatalf("%+v", v)
	}
}

func TestBadNowIsConfigError(t *testing.T) {
	alerts, policy := goodArgs(t)
	code, out, errs := run(t, "evaluate", "--alerts", alerts, "--policy", policy, "--now", "yesterday")
	if code != ExitConfig || out != "" || !strings.Contains(errs, "RFC3339") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
}

// An --alerts file over the size cap is an input error, never a verdict.
func TestAlertsSizeCap(t *testing.T) {
	_, policy := goodArgs(t)
	big := bytes.Repeat([]byte(" "), maxInputBytes+1)
	p := writeTemp(t, "big.json", big)
	code, out, errs := run(t, "evaluate", "--alerts", p, "--policy", policy)
	if code != ExitInput || out != "" || !strings.Contains(errs, "invalid_input") || !strings.Contains(errs, "16 MiB") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
}

func TestMissingFilesExitByRole(t *testing.T) {
	alerts, policy := goodArgs(t)
	if code, _, errs := run(t, "evaluate", "--alerts", "/nonexistent/a.json", "--policy", policy); code != ExitInput {
		t.Errorf("missing alerts: exit %d (stderr %q)", code, errs)
	}
	if code, _, errs := run(t, "evaluate", "--alerts", alerts, "--policy", "/nonexistent/p.yaml"); code != ExitPolicy {
		t.Errorf("missing policy: exit %d (stderr %q)", code, errs)
	}
}

// A policy file over the cap is a policy error.
func TestPolicySizeCap(t *testing.T) {
	alerts, _ := goodArgs(t)
	p := writeTemp(t, "big.yaml", bytes.Repeat([]byte("#"), maxInputBytes+1))
	if code, _, errs := run(t, "evaluate", "--alerts", alerts, "--policy", p); code != ExitPolicy {
		t.Errorf("exit %d (stderr %q)", code, errs)
	}
}
