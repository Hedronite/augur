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

// Vigil's contract (Hedronite/vigil 44dfb0b, schema/vigil.summary.v0.schema.json
// and docs/semantics.md section 4). A3b vendors the schema itself; until then
// these are copied here, and the tests below fail if our side drifts.
const (
	vigilReasonPattern = `^[a-z][a-z0-9_]{0,47}$`
	vigilSlugPattern   = `^[a-z0-9][a-z0-9\-]{0,31}$`
)

var vigilOwnReasons = []string{"source_stale", "source_unavailable", "schema_major", "clock_skew", "authority_unavailable"}

// No Augur code may equal one of Vigil's five: Vigil concatenates its own codes
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

// Our slug is exactly Vigil's, so a host or replica in the verdict can never
// fail Vigil's slug check (no leading dash, at most 32 characters).
func TestSlugEqualsVigilsSlug(t *testing.T) {
	// Vigil writes the hyphen escaped inside the class; ours does not.
	if got, want := strings.ReplaceAll(model.SlugPattern.String(), `\-`, `-`), strings.ReplaceAll(vigilSlugPattern, `\-`, `-`); got != want {
		t.Fatalf("slug pattern %s differs from Vigil's %s", got, want)
	}
	for in, ok := range map[string]bool{"-host": false, "host-": true, "host--a": true, "-": false, "a": true, strings.Repeat("a", 32): true, strings.Repeat("a", 33): false} {
		if _, matched := model.ResolveSlug(in); matched != ok {
			t.Errorf("ResolveSlug(%q) matched=%v, want %v", in, matched, ok)
		}
	}
}
