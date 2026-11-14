// Package decode turns saved or polled bytes into a model.Snapshot. It is the
// only code that reads untrusted alert JSON, and it enforces the output bounds
// on name and source_severity (see model.NamePattern and friends).
//
// Host and replica values are deliberately not resolved here: their label names
// come from the policy, which the decoder never sees. The engine resolves them
// with model.ResolveSlug.
//
// Field names are matched exactly, as the input schema matches them. The
// standard library's struct decoding is case-insensitive, which would let an
// unrelated field such as "STARTSAT" stand in for "startsAt"; that is a shape
// the schema rejects, so the decoder walks the object itself.
package decode

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Hedronite/augur/internal/model"
)

// Kind is the detected shape of an input document.
type Kind string

// Detected input kinds.
const (
	KindAMv2        Kind = "alertmanager_v2"
	KindAMWebhookV4 Kind = "alertmanager_webhook_v4"
	KindGrafana     Kind = "grafana_contact_point"
	KindUnknown     Kind = "unknown"
)

// ErrUnsupported reports a recognised but unsupported payload (exit 3, code
// unsupported_payload). Kind is the detail, for example
// alertmanager_webhook_v4.
type ErrUnsupported struct{ Kind Kind }

// Error implements error.
func (e *ErrUnsupported) Error() string { return "unsupported_payload: " + string(e.Kind) }

// ErrMalformed reports input that is not a valid Alertmanager v2 array
// (exit 3, code invalid_input). Detail is a short, bounded phrase: it names a
// field path and never echoes a label value.
type ErrMalformed struct{ Detail string }

// Error implements error.
func (e *ErrMalformed) Error() string { return "invalid_input: " + e.Detail }

// Limits that keep a hostile document from forcing unbounded work. They sit
// above anything the input schema requires, so the differential test treats
// them as the only sanctioned way for the decoder to reject what the schema
// accepts.
const (
	// MaxAlerts caps the number of alerts in one document.
	MaxAlerts = 100_000
	// MaxLabelsPerAlert caps the label set of a single alert.
	MaxLabelsPerAlert = 1_000
)

// timestampPattern is RFC3339 as the input schema's date-time format means it:
// an upper or lower case T and Z (RFC3339 permits both), an optional fraction
// with a dot, and an offset whose hour cannot exceed 23. The pattern is narrow
// on purpose so that the decoder accepts exactly what the schema accepts; a
// comma fraction and a +24:00 offset are rejected here because the schema
// rejects them, even though time.Parse would take both.
var timestampPattern = regexp.MustCompile(
	`^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$`)

// grafanaMarkerKeys are alert fields only Grafana's contact-point payload
// carries. Their presence identifies the document even when it also looks like
// an Alertmanager webhook.
var grafanaMarkerKeys = []string{"valueString", "values"}

// nullJSON is the literal JSON null, which every optional field must
// distinguish from an absent one.
var nullJSON = []byte("null")

// Sniff classifies data without fully decoding it.
//
// It returns a Kind and a nil error for every document it can classify, which
// includes the payloads Augur refuses: the caller turns a Kind other than
// KindAMv2 into ErrUnsupported, so the reason reaches the user as
// unsupported_payload. A non-nil error means the bytes are not JSON at all, or
// not a JSON array or object, and is always an *ErrMalformed.
func Sniff(data []byte) (Kind, error) {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 {
		return KindUnknown, &ErrMalformed{Detail: "the document is empty"}
	}
	switch trimmed[0] {
	case '[':
		if !json.Valid(trimmed) {
			return KindUnknown, &ErrMalformed{Detail: "malformed JSON"}
		}
		return KindAMv2, nil
	case '{':
		return sniffObject(trimmed)
	default:
		return KindUnknown, &ErrMalformed{Detail: "expected a JSON array of alerts"}
	}
}

// sniffObject classifies a top-level JSON object.
func sniffObject(data []byte) (Kind, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return KindUnknown, &ErrMalformed{Detail: "malformed JSON"}
	}
	if v, ok := jsonString(obj["version"]); ok && strings.HasPrefix(v, "4") {
		return KindAMWebhookV4, nil
	}
	if alerts, ok := obj["alerts"]; ok && hasGrafanaMarkers(alerts) {
		return KindGrafana, nil
	}
	if _, ok := obj["groupKey"]; ok {
		return KindAMWebhookV4, nil
	}
	if _, ok := obj["message"]; ok {
		return KindGrafana, nil
	}
	return KindUnknown, nil
}

// hasGrafanaMarkers reports whether any alert in the array carries a field only
// Grafana sends.
func hasGrafanaMarkers(raw json.RawMessage) bool {
	var alerts []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &alerts); err != nil {
		return false
	}
	for _, a := range alerts {
		for _, k := range grafanaMarkerKeys {
			if _, ok := a[k]; ok {
				return true
			}
		}
	}
	return false
}

// jsonString decodes a JSON string, reporting whether it was one.
func jsonString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var s *string
	if err := json.Unmarshal(raw, &s); err != nil || s == nil {
		return "", false
	}
	return *s, true
}

// DecodeAM decodes an Alertmanager v2 alerts array. The returned Snapshot has
// SourceID, State and LastOK unset; the caller fills them. Unknown fields in
// an alert are ignored; the overall shape must match.
//
//nolint:revive // the name is fixed by the A1 dispatch and used across packages
func DecodeAM(data []byte) (model.Snapshot, error) {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 {
		return model.Snapshot{}, &ErrMalformed{Detail: "the document is empty"}
	}
	if trimmed[0] != '[' {
		kind, err := Sniff(trimmed)
		if err != nil {
			return model.Snapshot{}, err
		}
		return model.Snapshot{}, &ErrUnsupported{Kind: kind}
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return model.Snapshot{}, &ErrMalformed{Detail: "malformed JSON"}
	}
	if len(raw) > MaxAlerts {
		return model.Snapshot{}, &ErrMalformed{Detail: "too many alerts"}
	}

	alerts := make([]model.Alert, 0, len(raw))
	for i, item := range raw {
		a, err := decodeAlert(item, i)
		if err != nil {
			return model.Snapshot{}, err
		}
		alerts = append(alerts, a)
	}
	return model.Snapshot{Alerts: alerts}, nil
}

// decodeAlert decodes one alert, applying the output bounds. i is the position
// in the array and appears in every error path.
func decodeAlert(item json.RawMessage, i int) (model.Alert, *ErrMalformed) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(item, &fields); err != nil {
		return model.Alert{}, &ErrMalformed{Detail: alertPath(i, "") + ": must be an object"}
	}

	labels, err := decodeLabels(fields["labels"], i)
	if err != nil {
		return model.Alert{}, err
	}
	alertName, ok := labels["alertname"]
	if !ok || alertName == "" {
		return model.Alert{}, malformed(i, "labels.alertname", "required")
	}

	starts, ok := requiredTime(fields["startsAt"])
	if !ok {
		if _, present := fields["startsAt"]; !present {
			return model.Alert{}, malformed(i, "startsAt", "required")
		}
		return model.Alert{}, malformed(i, "startsAt", "not an RFC3339 time")
	}
	if _, ok := optionalTime(fields["endsAt"]); !ok {
		return model.Alert{}, malformed(i, "endsAt", "not an RFC3339 time")
	}
	updated := starts
	if t, ok := optionalTime(fields["updatedAt"]); !ok {
		return model.Alert{}, malformed(i, "updatedAt", "not an RFC3339 time")
	} else if t != nil {
		updated = *t
	}

	state, err := decodeState(fields["status"], i)
	if err != nil {
		return model.Alert{}, err
	}

	a := model.Alert{
		Name:      boundName(alertName),
		Labels:    labels,
		State:     state,
		StartsAt:  starts,
		UpdatedAt: updated,
	}
	if sev, ok := labels["severity"]; ok && model.SeverityLabelPattern.MatchString(sev) {
		a.SourceSeverity = &sev
	}
	return a, nil
}

// decodeLabels reads the label set. Every value must be a JSON string, which is
// what the schema requires; a null value is not a string.
func decodeLabels(raw json.RawMessage, i int) (map[string]string, *ErrMalformed) {
	if len(raw) == 0 || bytes.Equal(raw, nullJSON) {
		return nil, malformed(i, "labels", "required")
	}
	var pairs map[string]json.RawMessage
	if err := json.Unmarshal(raw, &pairs); err != nil {
		return nil, malformed(i, "labels", "must be an object of strings")
	}
	if len(pairs) > MaxLabelsPerAlert {
		return nil, malformed(i, "labels", "too many labels")
	}
	keys := make([]string, 0, len(pairs))
	for k := range pairs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, len(pairs))
	for _, k := range keys {
		var s *string
		if err := json.Unmarshal(pairs[k], &s); err != nil || s == nil {
			// The label name is not echoed: a label set is user data.
			return nil, malformed(i, "labels", "every value must be a string")
		}
		out[k] = *s
	}
	return out, nil
}

// decodeState collapses Alertmanager's state and its two ID lists into the
// alert states the engine reasons about. A suppressed alert with neither list
// set is reported as inhibited, which fails towards "shown, doesn't raise".
func decodeState(raw json.RawMessage, i int) (model.AlertState, *ErrMalformed) {
	if len(raw) == 0 || bytes.Equal(raw, nullJSON) {
		return "", malformed(i, "status", "required")
	}
	var status map[string]json.RawMessage
	if err := json.Unmarshal(raw, &status); err != nil {
		return "", malformed(i, "status", "must be an object")
	}
	state, ok := jsonString(status["state"])
	if !ok {
		return "", malformed(i, "status", "required")
	}
	for _, field := range []string{"silencedBy", "inhibitedBy"} {
		if err := checkIDList(status[field], i, "status."+field); err != nil {
			return "", err
		}
	}
	switch state {
	case "active":
		return model.StateActive, nil
	case "unprocessed":
		return model.StateUnprocessed, nil
	case "suppressed":
		if len(idList(status["silencedBy"])) > 0 {
			return model.StateSilenced, nil
		}
		return model.StateInhibited, nil
	default:
		return "", malformed(i, "status.state", "must be one of active, suppressed, unprocessed")
	}
}

// idList returns the ID list, treating an absent or null field as empty. A
// non-array value yields nil; checkIDList rejects it.
func idList(raw json.RawMessage) []string {
	if len(raw) == 0 || bytes.Equal(raw, nullJSON) {
		return nil
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil
	}
	return ids
}

// checkIDList enforces the schema's rule that a present ID list is an array of
// strings.
func checkIDList(raw json.RawMessage, i int, field string) *ErrMalformed {
	if len(raw) == 0 || bytes.Equal(raw, nullJSON) {
		return nil
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		return malformed(i, field, "must be an array of strings")
	}
	return nil
}

// requiredTime parses a mandatory timestamp.
func requiredTime(raw json.RawMessage) (time.Time, bool) {
	s, ok := jsonString(raw)
	if !ok {
		return time.Time{}, false
	}
	return parseTimestamp(s)
}

// optionalTime parses an optional timestamp: a nil pointer when the field is
// absent, and ok false when it is present but not RFC3339.
func optionalTime(raw json.RawMessage) (*time.Time, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	s, ok := jsonString(raw)
	if !ok {
		return nil, false
	}
	t, ok := parseTimestamp(s)
	if !ok {
		return nil, false
	}
	return &t, true
}

// boundName returns the alert name if it is a bounded identifier, else the
// literal model.Unnamed. A raw label value never reaches the output.
func boundName(name string) string {
	if model.NamePattern.MatchString(name) {
		return name
	}
	return model.Unnamed
}

// parseTimestamp parses an RFC3339 timestamp whose acceptance set is the
// schema's date-time format, not merely whatever time.Parse tolerates.
func parseTimestamp(s string) (time.Time, bool) {
	if !timestampPattern.MatchString(s) {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, strings.ToUpper(s))
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// alertPath formats a field path inside an alert array.
func alertPath(i int, field string) string {
	if field == "" {
		return "alerts[" + strconv.Itoa(i) + "]"
	}
	return "alerts[" + strconv.Itoa(i) + "]." + field
}

// malformed builds an input error at a field path inside an alert.
func malformed(i int, field, problem string) *ErrMalformed {
	return &ErrMalformed{Detail: alertPath(i, field) + ": " + problem}
}
