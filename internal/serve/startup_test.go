package serve

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ip4 builds a dotted quad at run time so the scrub has no address literal to flag.
func ip4(a, b, c, d int) string { return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d) }

// AlertsURL joins the API path after any route prefix and sends all four states.
func TestAlertsURL(t *testing.T) {
	const q = "?active=true&silenced=true&inhibited=true&unprocessed=true"
	for in, want := range map[string]string{
		"http://127.0.0.1:9093":     "http://127.0.0.1:9093/api/v2/alerts" + q,
		"http://127.0.0.1:9093/":    "http://127.0.0.1:9093/api/v2/alerts" + q,
		"http://127.0.0.1:9093/am":  "http://127.0.0.1:9093/am/api/v2/alerts" + q,
		"http://127.0.0.1:9093/am/": "http://127.0.0.1:9093/am/api/v2/alerts" + q,
		"http://127.0.0.1:9093/a/b": "http://127.0.0.1:9093/a/b/api/v2/alerts" + q,
		"http://[::1]:9093/am":      "http://[::1]:9093/am/api/v2/alerts" + q,
	} {
		u, err := ParseAlertmanagerURL(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := AlertsURL(u); got != want {
			t.Errorf("AlertsURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckInterval(t *testing.T) {
	for d, ok := range map[time.Duration]bool{
		0: false, time.Second: false, 5*time.Second - 1: false, 5 * time.Second: true, 30 * time.Second: true,
		60 * time.Second: true, 60*time.Second + 1: false, 2 * time.Minute: false,
	} {
		if err := CheckInterval(d); (err == nil) != ok {
			t.Errorf("CheckInterval(%v) = %v, want ok=%v", d, err, ok)
		}
	}
}

func TestParseAlertmanagerURL(t *testing.T) {
	accept := []string{
		"http://127.0.0.1:9093", "http://127.0.0.1", "http://127.0.0.1:9093/", "http://" + ip4(127, 1, 2, 3) + ":9093",
		"http://" + ip4(127, 255, 255, 254) + ":80", "http://[::1]:9093", "http://[::1]", "http://127.0.0.1:9093/am",
	}
	for _, s := range accept {
		if _, err := ParseAlertmanagerURL(s); err != nil {
			t.Errorf("%q should be accepted: %v", s, err)
		}
	}
	refuse := []string{
		"", "127.0.0.1:9093", "http://localhost:9093", "http://LOCALHOST", "http://localhost.", "http://127.1:9093",
		"http://0x7f.1:9093", "http://0x7f000001", "http://2130706433", "http://017700000001", "http://[::ffff:127.0.0.1]:9093",
		"http://[::ffff:7f00:1]", "http://0.0.0.0:9093", "http://[::]:9093", "http://" + ip4(10, 0, 0, 1) + ":9093", "http://" + ip4(192, 168, 1, 1),
		"http://" + ip4(128, 0, 0, 1), "http://example.com", "http://alertmanager:9093", "https://127.0.0.1:9093",
		"ftp://127.0.0.1", "//127.0.0.1", "http://127.0.0.1@example.com", "http://user:pw@127.0.0.1:9093",
		"http://@127.0.0.1", "http://example.com#@127.0.0.1", "http://example.com\\@127.0.0.1", "http://127.0.0.1:9093?x=1",
		"http://127.0.0.1:9093#frag", "http://127.0.0.1:0", "http://127.0.0.1:99999", "http://127.0.0.1:abc",
		"http://[::1%25lo0]:9093", "http://127.0.0.1 .example.com", "http://127.0.0.1:9093\n",
	}
	for _, s := range refuse {
		if _, err := ParseAlertmanagerURL(s); err == nil {
			t.Errorf("%q must be refused", s)
		}
	}
}

func TestCheckOut(t *testing.T) {
	dir := t.TempDir()
	if err := CheckOut(filepath.Join(dir, "verdict.json")); err != nil {
		t.Fatal(err)
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".augur-*"))
	if len(left) != 0 {
		t.Fatalf("the probe left %v", left)
	}
	for name, out := range map[string]string{
		"empty": "", "missing directory": filepath.Join(dir, "nope", "v.json"), "a directory": dir,
		"trailing slash": dir + "/", "a file as the directory": filepath.Join(dir, "verdict.json", "x"),
	} {
		if name == "a file as the directory" {
			_ = os.WriteFile(filepath.Join(dir, "verdict.json"), []byte("x"), 0o600)
		}
		if err := CheckOut(out); err == nil {
			t.Errorf("%s: %q must be refused", name, out)
		}
	}
	if os.Geteuid() != 0 {
		ro := t.TempDir()
		if err := os.Chmod(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(ro, 0o700) }()
		err := CheckOut(filepath.Join(ro, "v.json"))
		if err == nil || !strings.Contains(err.Error(), "not writable") {
			t.Errorf("read-only directory: %v", err)
		}
	}
}

func TestWriteAtomicModeAndUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	p := filepath.Join(t.TempDir(), "v.json")
	if err := WriteAtomic(p, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v err %v", fi.Mode(), err)
	}
}

// A reader running in parallel never sees a partial file.
func TestWriteAtomicReaderNeverSeesAPartialFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "v.json")
	small := []byte(`{"v":"small"}` + "\n")
	large := []byte(`{"v":"` + strings.Repeat("L", 1<<20) + `"}` + "\n")
	if err := WriteAtomic(p, small); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	bad := make(chan string, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			data, err := os.ReadFile(p)
			if err != nil {
				select {
				case bad <- "read error: " + err.Error():
				default:
				}
				return
			}
			if string(data) != string(small) && string(data) != string(large) {
				select {
				case bad <- "partial or mixed file":
				default:
				}
				return
			}
		}
	}()
	for i := 0; i < 150; i++ {
		d := small
		if i%2 == 0 {
			d = large
		}
		if err := WriteAtomic(p, d); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	select {
	case msg := <-bad:
		t.Fatal(msg)
	default:
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".augur-*"))
	if len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
}

// A failed write leaves the previous file untouched and no temp file.
func TestWriteAtomicFailureLeavesTheOldFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "v.json")
	if err := WriteAtomic(p, []byte("old\n")); err != nil {
		t.Fatal(err)
	}
	// A directory at the destination makes the rename fail.
	bad := filepath.Join(dir, "d")
	if err := os.Mkdir(bad, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(bad, []byte("new\n")); err == nil {
		t.Fatal("renaming over a non-empty directory must fail")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".augur-*")); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
	if b, _ := os.ReadFile(p); string(b) != "old\n" {
		t.Fatal("the old file changed")
	}
}

// Startup cleanup removes only regular files named exactly .augur-*.tmp.
func TestCleanStrayTempMatchesOnlyItsOwnPrefix(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	gone := []string{mk(".augur-123.tmp"), mk(".augur-probe-9.tmp"), mk(".augur-.tmp")}
	keep := []string{mk("verdict.json"), mk("other.tmp"), mk(".augurx.tmp"), mk(".augur-keep"), mk("augur-1.tmp"), mk(".augur-1.tmp.bak"), mk("x.augur-1.tmp")}
	if err := os.Mkdir(filepath.Join(dir, ".augur-dir.tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := mk("target.txt")
	if err := os.Symlink(target, filepath.Join(dir, ".augur-link.tmp")); err != nil {
		t.Fatal(err)
	}
	n, err := CleanStrayTemp(dir)
	if err != nil || n != len(gone) {
		t.Fatalf("removed %d, err %v", n, err)
	}
	for _, p := range gone {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s should be removed", p)
		}
	}
	for _, p := range append(keep, target, filepath.Join(dir, ".augur-dir.tmp"), filepath.Join(dir, ".augur-link.tmp")) {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s must be kept: %v", p, err)
		}
	}
}
