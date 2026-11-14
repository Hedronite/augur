package render

import (
	"io"
	"strconv"
	"strings"
	"unicode"

	"github.com/Hedronite/augur/internal/model"
)

// excerptLimit bounds a FieldError excerpt. The policy parser already caps
// what it stores; this is the renderer's own guard, so nothing unbounded
// can reach an error line even if a future producer forgets.
const excerptLimit = 64

// Errors writes every FieldError for file in the house style: one location
// line per error (file:line, field path, bounded excerpt) followed by the
// problem and how to fix it. validate prints every error, never just the
// first. Excerpts are truncated, single-line and control-character-free;
// the raw value is never echoed.
func Errors(out io.Writer, file string, errs []model.FieldError) error {
	w := &errWriter{w: out}
	for _, e := range errs {
		loc := file
		if e.Line > 0 {
			loc = file + ":" + strconv.Itoa(e.Line)
		}
		w.printf("%s: %s: %s\n", loc, e.Path, excerpt(e.Value))
		if e.Problem != "" {
			w.printf("  problem: %s\n", e.Problem)
		}
		if e.Fix != "" {
			w.printf("  fix: %s\n", e.Fix)
		}
	}
	return w.err
}

// excerpt bounds one offending value for display: control characters
// (including newlines and tabs) are stripped so the excerpt is always a
// single line, whitespace is collapsed, and the result is truncated to
// excerptLimit runes with an ellipsis marker.
func excerpt(value string) string {
	var b strings.Builder
	lastSpace := false
	for _, r := range value {
		if unicode.IsControl(r) {
			continue
		}
		if unicode.IsSpace(r) {
			if !lastSpace {
				b.WriteRune(' ')
				lastSpace = true
			}
			continue
		}
		lastSpace = false
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "(empty)"
	}
	runes := []rune(out)
	if len(runes) > excerptLimit {
		return string(runes[:excerptLimit]) + "…"
	}
	return out
}
