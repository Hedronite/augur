// Package decode turns saved or polled bytes into a model.Snapshot. It is the
// only code that reads untrusted alert JSON, and it enforces the output
// bounds on name and source_severity (see model.NamePattern and friends).
package decode

import (
	"errors"
	"fmt"

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

// ErrUnsupported reports a recognised but unsupported payload (exit 3,
// code unsupported_payload). Kind is the detail, for example
// alertmanager_webhook_v4.
type ErrUnsupported struct{ Kind Kind }

func (e *ErrUnsupported) Error() string { return "unsupported_payload: " + string(e.Kind) }

// ErrMalformed reports input that is not a valid Alertmanager v2 array
// (exit 3, code invalid_input). It never carries raw input beyond a short,
// bounded excerpt.
type ErrMalformed struct {
	Detail string
}

func (e *ErrMalformed) Error() string { return "invalid_input: " + e.Detail }

var errNotImplemented = errors.New("not implemented")

// Sniff classifies data without fully decoding it.
func Sniff(_ []byte) (Kind, error) {
	return KindUnknown, fmt.Errorf("decode.Sniff: %w", errNotImplemented)
}

// DecodeAM decodes an Alertmanager v2 alerts array. The returned Snapshot has
// SourceID, State and LastOK unset; the caller fills them. Unknown fields in
// an alert are ignored; the overall shape must match.
//
//nolint:revive // the name is fixed by the A1 dispatch and used across packages
func DecodeAM(_ []byte) (model.Snapshot, error) {
	return model.Snapshot{}, fmt.Errorf("decode.DecodeAM: %w", errNotImplemented)
}
