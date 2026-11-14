// Package render writes verdicts and errors for people and for machines.
package render

import (
	"errors"
	"io"

	"github.com/Hedronite/augur/internal/model"
)

var errNotImplemented = errors.New("not implemented")

// Human writes the readable verdict: an overall line, a rollup of reasons,
// then one line per alert in the same order as the JSON. No colour unless w
// is a terminal.
func Human(_ io.Writer, _ model.Verdict) error { return errNotImplemented }

// JSON writes the canonical verdict document: sorted, byte-stable, ending in
// a newline.
func JSON(_ io.Writer, _ model.Verdict) error { return errNotImplemented }

// Errors writes every FieldError for file in the house style: file, field
// path, a short bounded excerpt and how to fix it.
func Errors(_ io.Writer, _ string, _ []model.FieldError) error { return errNotImplemented }
