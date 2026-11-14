package cli

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Hedronite/augur/internal/serve"
)

const servePolicyFixture = "../../testdata/fixtures/50-node-exporter-past-hold-single-view/policy.yaml"

func serveArgs(t *testing.T, extra ...string) (args []string, out string) {
	t.Helper()
	out = filepath.Join(t.TempDir(), "verdict.json")
	args = append([]string{"serve", "--policy", servePolicyFixture, "--alertmanager", "http://127.0.0.1:9093", "--out", out}, extra...)
	return args, out
}

// Every startup refusal is exit 5 with a message, and nothing is written.
func TestServeStartupRefusals(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"hostname", []string{"--alertmanager", "http://localhost:9093"}, "literal loopback"},
		{"non-loopback", []string{"--alertmanager", "http://" + fmt.Sprintf("%d.%d.%d.%d", 10, 0, 0, 1) + ":9093"}, "loopback"},
		{"https", []string{"--alertmanager", "https://127.0.0.1:9093"}, "http://"},
		{"short interval", []string{"--interval", "4s"}, "--interval"},
		{"long interval", []string{"--interval", "61s"}, "--interval"},
		{"missing out dir", []string{"--out", filepath.Join(dir, "no", "v.json")}, "--out"},
		{"unreadable policy", []string{"--policy", filepath.Join(dir, "none.yaml")}, "cannot read policy"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args, out := serveArgs(t)
			args = append(args, c.args...) // later flags win
			code, stdout, stderr := run(t, args...)
			if code != ExitConfig || stdout != "" || !strings.Contains(stderr, c.want) {
				t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
			}
			if _, err := os.Stat(out); err == nil && c.name != "missing out dir" {
				t.Fatal("a refused start must write nothing")
			}
		})
	}
}

// A policy that is read but invalid is exit 4, not 5.
func TestServeInvalidPolicyIsExit4(t *testing.T) {
	args, _ := serveArgs(t, "--policy", "../../testdata/fixtures/74-policy-green-default/policy.yaml")
	if code, _, stderr := run(t, args...); code != ExitPolicy || !strings.Contains(stderr, "invalid_policy") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

// A panic inside the loop is exit 6 and the old file is untouched.
func TestServePanicExits6AndLeavesTheOldFile(t *testing.T) {
	args, out := serveArgs(t)
	if err := os.WriteFile(out, []byte("old verdict\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	serveDepsHook = func(d *serve.Deps) { d.Client = panicDoer{} }
	defer func() { serveDepsHook = nil }()
	code, _, stderr := run(t, args...)
	if code != ExitInternal || !strings.Contains(stderr, "internal error") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if b, _ := os.ReadFile(out); string(b) != "old verdict\n" {
		t.Fatalf("the old file changed: %q", b)
	}
}

type panicDoer struct{}

func (panicDoer) Do(*http.Request) (*http.Response, error) { panic("boom") }

type recHandler struct {
	slog.Handler
	msgs chan string
}

func (h recHandler) Handle(ctx context.Context, r slog.Record) error {
	select {
	case h.msgs <- r.Message:
	default:
	}
	return h.Handler.Handle(ctx, r)
}

// SIGHUP is logged and ignored; SIGTERM finishes cleanly with exit 0.
func TestServeSignals(t *testing.T) {
	am := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"labels":{"alertname":"Watchdog","host":"host-a"},"startsAt":"2025-12-01T00:00:00Z","endsAt":"0001-01-01T00:00:00Z","updatedAt":"` +
			time.Now().UTC().Format(time.RFC3339) + `","fingerprint":"f","status":{"state":"active"}}]`))
	}))
	defer am.Close()
	args, out := serveArgs(t)
	args[4] = am.URL // --alertmanager value

	msgs := make(chan string, 64)
	wrote := make(chan struct{}, 8)
	serveDepsHook = func(d *serve.Deps) {
		d.Logger = slog.New(recHandler{Handler: slog.NewJSONHandler(&bytes.Buffer{}, nil), msgs: msgs})
		d.Write = func(p string, data []byte) error {
			err := serve.WriteAtomic(p, data)
			wrote <- struct{}{}
			return err
		}
	}
	defer func() { serveDepsHook = nil }()

	var wg sync.WaitGroup
	var code int
	var stderr string
	wg.Add(1)
	go func() {
		defer wg.Done()
		code, _, stderr = run(t, args...)
	}()
	waitFor := func(ch chan struct{}) {
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Error("timed out waiting for the first verdict")
		}
	}
	waitFor(wrote)
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(10 * time.Second)
loop:
	for {
		select {
		case m := <-msgs:
			if m == "sighup" {
				break loop
			}
		case <-deadline:
			t.Fatal("SIGHUP was not logged")
		}
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if code != ExitGreen {
		t.Fatalf("SIGTERM exit = %d, stderr %q", code, stderr)
	}
	if b, err := os.ReadFile(out); err != nil || !strings.Contains(string(b), `"overall": "GREEN"`) {
		t.Fatalf("verdict file: %v %q", err, b)
	}
}
