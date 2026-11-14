package serve

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Hedronite/augur/internal/decode"
	"github.com/Hedronite/augur/internal/model"
)

// Poll limits.
const (
	// MaxBody caps one response body, the same cap as `evaluate` input.
	MaxBody = 16 << 20
	// MaxAlerts caps the alerts one poll may carry. It is what keeps the
	// verdict under MaxVerdictBytes: a poll over the cap is a failed poll
	// (unreachable), which fails closed. TestVerdictFitsAtMaxAlerts shows that
	// even with every bounded field at its maximum (about 860 bytes an alert,
	// where a typical alert is about 314) the verdict fits. The decoder's own
	// cap is higher because `evaluate` has no output cap.
	MaxAlerts = 4000
	// MaxVerdictBytes is the reader's cap on the verdict file (4 MiB).
	MaxVerdictBytes = 4 << 20
	// maxTimeout bounds one request.
	maxTimeout = 10 * time.Second
)

// Failure kinds. They are enum values, safe to log; a failure never logs the
// body or the error text, which could carry input.
const (
	KindConnect  = "connect"
	KindTimeout  = "timeout"
	KindStatus   = "status"
	KindRedirect = "redirect"
	KindTooLarge = "too_large"
	KindDecode   = "decode"
	KindTooMany  = "too_many"
	KindCanceled = "canceled"
)

// PollError is a failed poll; Kind is one of the Kind constants.
type PollError struct{ Kind string }

// Error implements error.
func (e *PollError) Error() string { return "poll failed: " + e.Kind }

// Doer is the part of http.Client the poller uses.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// NewHTTPClient returns the poll client: no redirects followed, no proxy (the
// proxy environment variables are ignored), and no connection reuse that could
// outlive a poll.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:             nil,
			DialContext:       (&net.Dialer{Timeout: maxTimeout}).DialContext,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// RequestTimeout is min(10s, interval/2).
func RequestTimeout(interval time.Duration) time.Duration {
	t := interval / 2
	if t > maxTimeout {
		t = maxTimeout
	}
	return t
}

// AlertsURL is the explicit query: every alert state is requested.
func AlertsURL(base *url.URL) string {
	u := *base
	u.Path = joinPath(base.Path, "/api/v2/alerts")
	u.RawQuery = "active=true&silenced=true&inhibited=true&unprocessed=true"
	return u.String()
}

func joinPath(prefix, p string) string {
	for len(prefix) > 0 && prefix[len(prefix)-1] == '/' {
		prefix = prefix[:len(prefix)-1]
	}
	return prefix + p
}

// fetch reads one snapshot. It returns a *PollError for every failure.
func fetch(ctx context.Context, c Doer, target string, timeout time.Duration, userAgent string) (model.Snapshot, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		return model.Snapshot{}, &PollError{Kind: KindConnect}
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return model.Snapshot{}, &PollError{Kind: classify(ctx, err)}
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return model.Snapshot{}, &PollError{Kind: KindRedirect}
	case resp.StatusCode != http.StatusOK:
		return model.Snapshot{}, &PollError{Kind: KindStatus}
	case resp.ContentLength > MaxBody:
		return model.Snapshot{}, &PollError{Kind: KindTooLarge}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		return model.Snapshot{}, &PollError{Kind: classify(ctx, err)}
	}
	if len(data) > MaxBody {
		return model.Snapshot{}, &PollError{Kind: KindTooLarge}
	}
	snap, err := decode.DecodeAM(data)
	if err != nil {
		return model.Snapshot{}, &PollError{Kind: KindDecode}
	}
	if len(snap.Alerts) > MaxAlerts {
		return model.Snapshot{}, &PollError{Kind: KindTooMany}
	}
	return snap, nil
}

func classify(parent context.Context, err error) string {
	if parent.Err() != nil {
		return KindCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return KindTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return KindTimeout
	}
	return KindConnect
}
