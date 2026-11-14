package render

import (
	"fmt"
	"io"
)

// errWriter remembers the first write error so the renderers can print freely
// and report it once at the end.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	e.err = err
	return n, err
}

func (e *errWriter) printf(format string, args ...any) {
	_, _ = fmt.Fprintf(e, format, args...)
}
