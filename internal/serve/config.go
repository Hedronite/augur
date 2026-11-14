// Package serve is the poll loop behind `augur serve`: it reads the
// Alertmanager v2 API on loopback, classifies the snapshot, runs the dead-man
// tracker and writes the verdict file atomically. The loop takes an injected
// clock, ticker, HTTP client and writer so tests run with no sleeps.
package serve

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Interval bounds. The upper bound keeps the verdict file inside the consumer's
// 120 s stale_after.
const (
	MinInterval     = 5 * time.Second
	MaxInterval     = 60 * time.Second
	DefaultInterval = 30 * time.Second
)

// CheckInterval refuses an interval outside [MinInterval, MaxInterval].
func CheckInterval(d time.Duration) error {
	if d < MinInterval || d > MaxInterval {
		return fmt.Errorf("--interval must be between %s and %s (got %s); the upper bound keeps the verdict file inside the 120s stale_after of its reader",
			MinInterval, MaxInterval, d)
	}
	return nil
}

// ParseAlertmanagerURL accepts only http:// to a literal loopback address:
// 127.0.0.0/8 or [::1]. Names (localhost included), other spellings of
// 127.0.0.1 such as 127.1 or 0x7f.1, IPv4-mapped IPv6, user info and anything
// past a path are refused, because resolving or trusting them is a step the
// poller does not need. The path may carry a route prefix.
func ParseAlertmanagerURL(raw string) (*url.URL, error) {
	const fix = "use a literal loopback address, for example http://127.0.0.1:9093"
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("--alertmanager is not a valid URL; %s", fix)
	}
	if u.Scheme != "http" {
		return nil, fmt.Errorf("--alertmanager must use http:// (the poll stays on loopback); %s", fix)
	}
	if u.User != nil {
		return nil, errors.New("--alertmanager must not carry user info; " + fix)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, errors.New("--alertmanager must be a base URL without a query or fragment; " + fix)
	}
	host := u.Hostname()
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return nil, errors.New("--alertmanager host must be a literal loopback address, not a name; " + fix)
	}
	loopback := (addr.Is4() && addr.As4()[0] == 127) || addr == netip.IPv6Loopback()
	if !loopback {
		return nil, errors.New("--alertmanager must point at a loopback address (127.0.0.0/8 or [::1]); " + fix)
	}
	if p := u.Port(); p != "" {
		if n, perr := strconv.Atoi(p); perr != nil || n < 1 || n > 65535 {
			return nil, errors.New("--alertmanager port is out of range; " + fix)
		}
	}
	return u, nil
}

// tmpPrefix and tmpSuffix name every temp file the writer creates; startup
// cleanup removes only files that match both.
const (
	tmpPrefix = ".augur-"
	tmpSuffix = ".tmp"
)

// CheckOut refuses an --out whose directory is missing or not writable. It
// probes with a temp file and removes it.
func CheckOut(out string) error {
	if out == "" || strings.HasSuffix(out, string(os.PathSeparator)) {
		return errors.New("--out must name a file; for example /var/lib/augur/verdict.json")
	}
	if fi, err := os.Stat(out); err == nil && fi.IsDir() {
		return errors.New("--out is a directory; name a file inside it")
	}
	dir := filepath.Dir(out)
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return errors.New("--out directory does not exist; create it first and make it writable by the service user")
	}
	f, err := os.CreateTemp(dir, tmpPrefix+"probe-*"+tmpSuffix)
	if err != nil {
		return errors.New("--out directory is not writable; give the service user write access to it")
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}
