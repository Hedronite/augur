package decode

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Hedronite/augur/internal/model"
)

const fixturesDir = "../../testdata/fixtures"

// fixture is one testdata/fixtures directory, loaded.
type fixture struct {
	name    string
	alerts  []byte
	policy  []byte
	now     string
	expErr  *expectedError
	expJSON []byte
}

// expectedError mirrors expected_error.json.
type expectedError struct {
	Exit   int    `json:"exit"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func loadFixtures(t *testing.T) []fixture {
	t.Helper()
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var out []fixture
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(fixturesDir, e.Name())
		fx := fixture{
			name:   e.Name(),
			alerts: mustRead(t, filepath.Join(dir, "alerts.json")),
			policy: mustRead(t, filepath.Join(dir, "policy.yaml")),
			now:    strings.TrimSpace(string(mustRead(t, filepath.Join(dir, "now.txt")))),
		}
		if b, err := os.ReadFile(filepath.Join(dir, "expected_error.json")); err == nil {
			var exp expectedError
			if err := json.Unmarshal(b, &exp); err != nil {
				t.Fatalf("%s: expected_error.json: %v", e.Name(), err)
			}
			fx.expErr = &exp
		}
		if b, err := os.ReadFile(filepath.Join(dir, "expected.json")); err == nil {
			fx.expJSON = b
		}
		out = append(out, fx)
	}
	if len(out) == 0 {
		t.Fatal("no fixtures found")
	}
	return out
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// TestSniffFixtures checks that every fixture's input is classified the way its
// expected outcome implies.
func TestSniffFixtures(t *testing.T) {
	for _, fx := range loadFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			kind, err := Sniff(fx.alerts)
			switch {
			case fx.expErr == nil:
				if err != nil {
					t.Fatalf("Sniff returned %v, want no error", err)
				}
				if kind != KindAMv2 {
					t.Fatalf("Sniff = %q, want %q", kind, KindAMv2)
				}
			case fx.expErr.Code == "unsupported_payload":
				if err != nil {
					t.Fatalf("Sniff returned %v, want no error for a recognised payload", err)
				}
				if string(kind) != fx.expErr.Detail {
					t.Fatalf("Sniff = %q, want %q", kind, fx.expErr.Detail)
				}
			case fx.expErr.Code == "invalid_policy":
				// Exit 4 is the policy's fault; the alert input is fine.
				if err != nil {
					t.Fatalf("Sniff returned %v, want no error", err)
				}
				if kind != KindAMv2 {
					t.Fatalf("Sniff = %q, want %q", kind, KindAMv2)
				}
			default:
				// Not JSON at all: Sniff names why. Valid JSON the decoder
				// refuses keeps KindAMv2 and fails in DecodeAM instead.
				if err == nil {
					if kind != KindAMv2 {
						t.Fatalf("Sniff = %q, want %q", kind, KindAMv2)
					}
					if _, derr := DecodeAM(fx.alerts); derr == nil {
						t.Fatal("DecodeAM accepted the input the fixture rejects")
					} else {
						var dem *ErrMalformed
						if !errors.As(derr, &dem) || dem.Detail == "" {
							t.Fatalf("DecodeAM err = %v, want an *ErrMalformed with a detail", derr)
						}
					}
					return
				}
				var em *ErrMalformed
				if !errors.As(err, &em) || em.Detail == "" {
					t.Fatalf("Sniff returned %v, want an *ErrMalformed with a detail", err)
				}
			}
		})
	}
}

// TestDecodeErrorFixtures checks the exit-3 fixtures end to end through
// DecodeAM, including the typed error the CLI maps to a code.
func TestDecodeErrorFixtures(t *testing.T) {
	for _, fx := range loadFixtures(t) {
		if fx.expErr == nil || fx.expErr.Exit != 3 {
			continue
		}
		t.Run(fx.name, func(t *testing.T) {
			_, err := DecodeAM(fx.alerts)
			if err == nil {
				t.Fatal("DecodeAM accepted input the fixture rejects")
			}
			var eu *ErrUnsupported
			var em *ErrMalformed
			switch fx.expErr.Code {
			case "unsupported_payload":
				if !errors.As(err, &eu) {
					t.Fatalf("err = %v, want *ErrUnsupported", err)
				}
				if string(eu.Kind) != fx.expErr.Detail {
					t.Fatalf("Kind = %q, want %q", eu.Kind, fx.expErr.Detail)
				}
			case "invalid_input":
				// The fixture's detail is a hint (INDEX note 15); exit and code
				// are the contract, so only the typed error is asserted.
				if !errors.As(err, &em) || em.Detail == "" {
					t.Fatalf("err = %v, want an *ErrMalformed with a detail", err)
				}
			default:
				t.Fatalf("unexpected code %q", fx.expErr.Code)
			}
		})
	}
}

// TestDecodeVerdictFixtures checks every successful fixture decodes to the
// advertised number of alerts, with every output string inside its bound.
func TestDecodeVerdictFixtures(t *testing.T) {
	for _, fx := range loadFixtures(t) {
		if fx.expErr != nil {
			continue
		}
		t.Run(fx.name, func(t *testing.T) {
			snap, err := DecodeAM(fx.alerts)
			if err != nil {
				t.Fatalf("DecodeAM: %v", err)
			}
			var want struct {
				Sources []struct {
					AlertCount int `json:"alert_count"`
				} `json:"sources"`
			}
			if err := json.Unmarshal(fx.expJSON, &want); err != nil {
				t.Fatalf("expected.json: %v", err)
			}
			if got := len(snap.Alerts); got != want.Sources[0].AlertCount {
				t.Fatalf("decoded %d alerts, expected.json says %d", got, want.Sources[0].AlertCount)
			}
			for _, a := range snap.Alerts {
				if a.Name != model.Unnamed && !model.NamePattern.MatchString(a.Name) {
					t.Errorf("name %q is outside its bound", a.Name)
				}
				if a.SourceSeverity != nil && !model.SeverityLabelPattern.MatchString(*a.SourceSeverity) {
					t.Errorf("source_severity %q is outside its bound", *a.SourceSeverity)
				}
				if a.State == "" {
					t.Errorf("%s: empty state", a.Name)
				}
			}
		})
	}
}

// TestBounds locks the M6 bounds at decode time.
func TestBounds(t *testing.T) {
	cases := []struct {
		name     string
		labels   map[string]string
		wantName string
		wantSev  *string
	}{
		{"valid name and severity", map[string]string{"alertname": "Node_Exporter:Down", "severity": "warning"},
			"Node_Exporter:Down", ptr("warning")},
		{"name with a space", map[string]string{"alertname": "Node Exporter Down"}, model.Unnamed, nil},
		{"name too long", map[string]string{"alertname": strings.Repeat("A", 129)}, model.Unnamed, nil},
		{"name starting with a digit", map[string]string{"alertname": "9Lives"}, model.Unnamed, nil},
		{"severity upper case", map[string]string{"alertname": "W", "severity": "Critical"}, "W", nil},
		{"severity too long", map[string]string{"alertname": "W", "severity": strings.Repeat("a", 33)}, "W", nil},
		{"no severity label", map[string]string{"alertname": "W"}, "W", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := alertJSON(tc.labels, "2026-01-15T11:00:00Z", `"active"`)
			snap, err := DecodeAM(body)
			if err != nil {
				t.Fatalf("DecodeAM: %v", err)
			}
			a := snap.Alerts[0]
			if a.Name != tc.wantName {
				t.Errorf("name = %q, want %q", a.Name, tc.wantName)
			}
			switch {
			case tc.wantSev == nil && a.SourceSeverity != nil:
				t.Errorf("source_severity = %q, want nil", *a.SourceSeverity)
			case tc.wantSev != nil && (a.SourceSeverity == nil || *a.SourceSeverity != *tc.wantSev):
				t.Errorf("source_severity = %v, want %q", a.SourceSeverity, *tc.wantSev)
			}
		})
	}
}

func ptr(s string) *string { return &s }

// TestStateMapping locks how Alertmanager's state and ID lists collapse.
func TestStateMapping(t *testing.T) {
	cases := []struct {
		name   string
		status string
		want   model.AlertState
	}{
		{"active", `{"state":"active"}`, model.StateActive},
		{"unprocessed", `{"state":"unprocessed"}`, model.StateUnprocessed},
		{"suppressed and silenced", `{"state":"suppressed","silencedBy":["s1"]}`, model.StateSilenced},
		{"suppressed and inhibited", `{"state":"suppressed","inhibitedBy":["i1"]}`, model.StateInhibited},
		{"suppressed with neither list", `{"state":"suppressed"}`, model.StateInhibited},
		{"suppressed with both lists", `{"state":"suppressed","silencedBy":["s1"],"inhibitedBy":["i1"]}`, model.StateSilenced},
		{"empty silencedBy", `{"state":"active","silencedBy":[]}`, model.StateActive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `[{"labels":{"alertname":"W"},"startsAt":"2026-01-15T11:00:00Z","status":` + tc.status + `}]`
			snap, err := DecodeAM([]byte(body))
			if err != nil {
				t.Fatalf("DecodeAM: %v", err)
			}
			if got := snap.Alerts[0].State; got != tc.want {
				t.Fatalf("state = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestTimestamps pins the acceptance set to the schema, which now carries a
// date-time pattern beside the format keyword. The decoder implements the
// stricter of the two: the pattern decides the shape, and the format decides
// the offset range, so +24:00 and a comma fraction are out.
func TestTimestamps(t *testing.T) {
	accept := []string{
		"2026-01-15T11:00:00Z",
		"2026-01-15T11:00:00.000Z",
		"2026-01-15T11:00:00.123456789Z",
		"2026-01-15T11:00:00+00:00",
		"2026-01-15T11:00:00-00:00",
		"2026-01-15T23:59:59+23:59",
		"0001-01-01T00:00:00Z",
		"2024-02-29T00:00:00Z",
	}
	reject := []string{
		"garbage",
		"2026-01-15T11:00:00",
		"2026-01-15 11:00:00Z",
		"2026-01-15t11:00:00z",            // the pattern requires upper case T and Z
		"2026-01-15T11:00:00.1234567890Z", // more than 9 fraction digits
		"2026-01-15T11:00:00,5Z",          // comma fraction: the schema rejects it
		"2026-01-15T11:00:00+24:00",
		"2026-01-15T11:00:00+05:60",
		"2026-02-30T00:00:00Z",
		"2026-04-31T00:00:00Z",
		"2026-13-01T00:00:00Z",
		"2026-01-15T24:00:00Z",
		"2026-01-15T11:00:60Z",
		"20260115T110000Z",
		"2026-01-15T11:00:00ZB",
	}
	for _, ts := range accept {
		t.Run("accept "+ts, func(t *testing.T) {
			if _, err := DecodeAM(alertJSON(map[string]string{"alertname": "W"}, ts, `"active"`)); err != nil {
				t.Fatalf("DecodeAM rejected %q: %v", ts, err)
			}
		})
	}
	for _, ts := range reject {
		t.Run("reject "+ts, func(t *testing.T) {
			var em *ErrMalformed
			_, err := DecodeAM(alertJSON(map[string]string{"alertname": "W"}, ts, `"active"`))
			if !errors.As(err, &em) {
				t.Fatalf("DecodeAM accepted %q (err = %v)", ts, err)
			}
			if em.Detail != "alerts[0].startsAt: not an RFC3339 time" {
				t.Fatalf("Detail = %q", em.Detail)
			}
		})
	}
}

// TestErrorNeverEchoesLabelValues is the QA invariant: a raw label value must
// not reach an error message, whatever is wrong with the alert.
func TestErrorNeverEchoesLabelValues(t *testing.T) {
	const secret = "s3cr3t-hostname-01"
	bodies := []string{
		`[{"labels":{"alertname":"W","host":"` + secret + `"},"startsAt":"nope","status":{"state":"active"}}]`,
		`[{"labels":{"alertname":"W","host":"` + secret + `"},"startsAt":"2026-01-15T11:00:00Z","status":{"state":"bad"}}]`,
		`[{"labels":{"alertname":"W","host":"` + secret + `"},"startsAt":"2026-01-15T11:00:00Z","status":{"state":"active","silencedBy":"` + secret + `"}}]`,
		`[{"labels":{"alertname":"W","host":"` + secret + `"},"startsAt":"2026-01-15T11:00:00Z","status":{"state":"active"},"endsAt":"` + secret + `"}]`,
	}
	for i, body := range bodies {
		_, err := DecodeAM([]byte(body))
		if err == nil {
			t.Fatalf("case %d: expected an error", i)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("case %d: error echoed a label value: %v", i, err)
		}
	}
}

// TestCaps keeps a hostile document from forcing unbounded work.
func TestCaps(t *testing.T) {
	t.Run("too many alerts", func(t *testing.T) {
		one := `{"labels":{"alertname":"W"},"startsAt":"2026-01-15T11:00:00Z","status":{"state":"active"}}`
		body := "[" + strings.Repeat(one+",", MaxAlerts) + one + "]"
		var em *ErrMalformed
		if _, err := DecodeAM([]byte(body)); !errors.As(err, &em) || em.Detail != "too many alerts" {
			t.Fatalf("err = %v, want the alert-count cap", err)
		}
	})
	t.Run("too many labels", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(`[{"labels":{"alertname":"W"`)
		for i := 0; i <= MaxLabelsPerAlert; i++ {
			b.WriteString(`,"l`)
			b.WriteString(strconv.Itoa(i))
			b.WriteString(`":"v"`)
		}
		b.WriteString(`},"startsAt":"2026-01-15T11:00:00Z","status":{"state":"active"}}]`)
		var em *ErrMalformed
		if _, err := DecodeAM([]byte(b.String())); !errors.As(err, &em) || em.Detail != "alerts[0].labels: too many labels" {
			t.Fatalf("err = %v, want the label-count cap", err)
		}
	})
}

// alertJSON builds a one-alert array around the given labels and timestamp.
func alertJSON(labels map[string]string, startsAt, state string) []byte {
	enc, err := json.Marshal(labels)
	if err != nil {
		panic(err)
	}
	return []byte(`[{"labels":` + string(enc) + `,"startsAt":"` + startsAt + `","status":{"state":` + state + `}}]`)
}

// TestUpdatedAtFallback documents that a missing updatedAt falls back to
// startsAt, which is what the verdict's watchdog.last_seen reads.
func TestUpdatedAtFallback(t *testing.T) {
	snap, err := DecodeAM(alertJSON(map[string]string{"alertname": "W"}, "2026-01-15T11:00:00Z", `"active"`))
	if err != nil {
		t.Fatalf("DecodeAM: %v", err)
	}
	if !snap.Alerts[0].UpdatedAt.Equal(snap.Alerts[0].StartsAt) {
		t.Fatalf("UpdatedAt = %v, want the start time", snap.Alerts[0].UpdatedAt)
	}
	body := `[{"labels":{"alertname":"W"},"startsAt":"2026-01-15T11:00:00Z","updatedAt":"2026-01-15T11:30:00Z","status":{"state":"active"}}]`
	snap, err = DecodeAM([]byte(body))
	if err != nil {
		t.Fatalf("DecodeAM: %v", err)
	}
	if got, want := snap.Alerts[0].UpdatedAt, time.Date(2026, 1, 15, 11, 30, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("UpdatedAt = %v, want %v", got, want)
	}
}

// TestDeclaredPropertiesAreTyped: every property am-alerts.v2.json types is
// checked, including the ones Augur never reads, so a document the schema
// rejects is never reported as valid. The fingerprint case came from CI.
func TestDeclaredPropertiesAreTyped(t *testing.T) {
	// base is a valid alert; each row adds or replaces one declared field.
	const base = `"labels":{"alertname":"Watchdog","host":"host-a"},"startsAt":"2026-01-15T11:00:00Z"`
	withStatus := func(extra, status string) string {
		return "{" + base + extra + `,"status":` + status + "}"
	}
	active := `{"state":"active"}`
	reject := map[string]struct{ doc, field string }{
		"fingerprint is an object":  {withStatus(`,"fingerprint":{}`, active), "fingerprint"},
		"fingerprint is null":       {withStatus(`,"fingerprint":null`, active), "fingerprint"},
		"generatorURL is a number":  {withStatus(`,"generatorURL":7`, active), "generatorURL"},
		"annotations is an array":   {withStatus(`,"annotations":[]`, active), "annotations"},
		"annotations is null":       {withStatus(`,"annotations":null`, active), "annotations"},
		"annotation value a number": {withStatus(`,"annotations":{"summary":1}`, active), "annotations"},
		"endsAt is an array":        {withStatus(`,"endsAt":[]`, active), "endsAt"},
		"updatedAt is an object":    {withStatus(`,"updatedAt":{}`, active), "updatedAt"},
		"silencedBy is null": {
			withStatus("", `{"state":"suppressed","silencedBy":null}`), "status.silencedBy",
		},
		"inhibitedBy is a string": {
			withStatus("", `{"state":"suppressed","inhibitedBy":"id"}`), "status.inhibitedBy",
		},
		"status is an array": {withStatus("", `[]`), "status"},
		"labels is a string": {
			`{"labels":"labels","startsAt":"2026-01-15T11:00:00Z","status":{"state":"active"}}`, "labels",
		},
		"label value is a number": {
			`{"labels":{"alertname":"A","n":1},"startsAt":"2026-01-15T11:00:00Z","status":{"state":"active"}}`, "labels",
		},
	}
	for name, tc := range reject {
		t.Run(name, func(t *testing.T) {
			var em *ErrMalformed
			if _, err := DecodeAM([]byte("[" + tc.doc + "]")); !errors.As(err, &em) {
				t.Fatalf("DecodeAM accepted %s (err = %v)", name, err)
			} else if want := "alerts[0]." + tc.field + ":"; !strings.HasPrefix(em.Detail, want) {
				t.Fatalf("Detail = %q, want the prefix %q", em.Detail, want)
			}
		})
	}

	accept := map[string]string{
		"every declared field well typed": withStatus(
			`,"fingerprint":"abc","generatorURL":"https://example.invalid/g",`+
				`"annotations":{"summary":"s","description":"d"},"endsAt":"0001-01-01T00:00:00Z",`+
				`"updatedAt":"2026-01-15T11:58:00Z"`,
			`{"state":"suppressed","silencedBy":[],"inhibitedBy":[]}`),
		// Undeclared fields stay ignored: the schema allows them, so the
		// decoder must accept them whatever they hold.
		"unknown fields are ignored": withStatus(`,"receivers":{},"mutedBy":{},"values":{"a":1}`, active),
	}
	for name, doc := range accept {
		t.Run("accepts "+name, func(t *testing.T) {
			if _, err := DecodeAM([]byte("[" + doc + "]")); err != nil {
				t.Fatalf("DecodeAM rejected %s: %v", name, err)
			}
		})
	}
}
