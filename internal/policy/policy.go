// Package policy parses and validates an augur.policy/v0 document.
package policy

import (
	"errors"

	"github.com/Hedronite/augur/internal/model"
)

var errNotImplemented = errors.New("policy.Parse: not implemented")

// Parse reads strict YAML (unknown keys are errors) and returns the policy
// with defaults applied and SHA256 set. It collects every problem rather than
// stopping at the first; a non-empty slice means exit 4. The error return is
// reserved for failures that are not the policy's fault.
func Parse(_ []byte) (model.Policy, []model.FieldError) {
	return model.Policy{}, []model.FieldError{{Problem: errNotImplemented.Error()}}
}
