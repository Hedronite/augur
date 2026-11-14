package model_test

import (
	"encoding/json"
	"os"
	"sort"
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
