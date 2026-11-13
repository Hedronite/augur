// Package cli implements the augur command line.
package cli

// Exit codes. Only "0 to 2 versus 3 and up" is the public contract: 0, 1 and 2
// are the GREEN, YELLOW and RED verdicts, and everything from 3 up means no
// verdict was produced.
const (
	ExitGreen    = 0 // GREEN verdict
	ExitYellow   = 1 // YELLOW verdict
	ExitRed      = 2 // RED verdict
	ExitInput    = 3 // bad or unsupported input
	ExitPolicy   = 4 // invalid policy
	ExitConfig   = 5 // config, usage or startup error
	ExitInternal = 6 // internal error, including "not implemented" and recovered panics
)

// exitError carries an exit code out of a command.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }
