package model_test

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Hedronite/augur/internal/model"
)

// TestReasonsMatchVerdictSchema keeps the Go enum and verdict.v0.json equal.
func TestReasonsMatchVerdictSchema(t *testing.T) {
	raw, err := os.ReadFile("../../schema/verdict.v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Defs struct {
			Reason struct {
				Enum []string `json:"enum"`
			} `json:"reason"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	want := doc.Defs.Reason.Enum
	sort.Strings(want)

	var got []string
	for _, r := range model.AllReasons() {
		got = append(got, string(r))
	}
	if len(got) != len(want) {
		t.Fatalf("reason count: go %d, schema %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("reason %d: go %q, schema %q", i, got[i], want[i])
		}
	}
}

func TestSeverityRank(t *testing.T) {
	if model.Worse(model.Green, model.Yellow) != model.Yellow ||
		model.Worse(model.Red, model.Yellow) != model.Red ||
		model.Worse(model.Yellow, model.Yellow) != model.Yellow {
		t.Fatal("Worse is wrong")
	}
	if model.Severity("bogus").Rank() <= model.Red.Rank() {
		t.Fatal("an unknown severity must rank above RED")
	}
}

func TestResolveSlug(t *testing.T) {
	for in, ok := range map[string]bool{"host-a": true, "r1": true, "": false, "Host": false, "a b": false} {
		got, matched := model.ResolveSlug(in)
		if matched != ok {
			t.Errorf("ResolveSlug(%q) matched=%v, want %v", in, matched, ok)
		}
		if !ok && got != model.Unmapped {
			t.Errorf("ResolveSlug(%q) = %q, want %q", in, got, model.Unmapped)
		}
	}
}

// Vigil's contract (Hedronite/vigil 5a7d7d1, schema/vigil.summary.v0.schema.json
// and docs/semantics.md section 4). The schema is vendored under
// testdata/vigil/vendor; these are copies from that commit, and the tests below
// fail if our side drifts from them.
const (
	vigilReasonPattern = `^[a-z][a-z0-9_]{0,47}$`
	vigilSlugPattern   = `^[a-z][a-z0-9\-]{0,31}$`
)

var vigilOwnReasons = []string{"source_stale", "source_unavailable", "schema_major", "clock_skew", "authority_unavailable", "declaration_drift"}

// No Augur code may equal one of Vigil's own: Vigil concatenates its own codes
// and an authority's into one flat verdicts[].reasons, so a shared string would
// be ambiguous.
func TestNoReasonCollidesWithVigil(t *testing.T) {
	for _, r := range model.AllReasons() {
		for _, v := range vigilOwnReasons {
			if string(r) == v {
				t.Errorf("reason %q is one of Vigil's own codes", r)
			}
		}
	}
}

// Every code must pass Vigil's shape check, or Vigil would drop the verdict.
func TestEveryReasonFitsVigilsPattern(t *testing.T) {
	re := regexp.MustCompile(vigilReasonPattern)
	for _, r := range model.AllReasons() {
		if !re.MatchString(string(r)) {
			t.Errorf("reason %q does not match Vigil's reason pattern %s", r, vigilReasonPattern)
		}
	}
}

// Our slug is Vigil's with one allowance: it may start with a digit, where
// Vigil's starts with a letter. Hosts and replicas travel in augur{}, which
// Vigil's schema does not hold to its slug, so no verdict is refused for it.
// Either side moving fails here.
func TestSlugAgainstVigilsSlug(t *testing.T) {
	vigil := regexp.MustCompile(vigilSlugPattern)
	for in, ok := range map[string]bool{
		"-host": false, "host-": true, "host--a": true, "-": false, "a": true, "9host": true, "0": true,
		strings.Repeat("a", 32): true, strings.Repeat("a", 33): false,
	} {
		if _, matched := model.ResolveSlug(in); matched != ok {
			t.Errorf("ResolveSlug(%q) matched=%v, want %v", in, matched, ok)
		}
		leadingDigit := in != "" && in[0] >= '0' && in[0] <= '9'
		if got, want := vigil.MatchString(in), ok && !leadingDigit; got != want {
			t.Errorf("Vigil slug match for %q = %v, want %v", in, got, want)
		}
	}
}
