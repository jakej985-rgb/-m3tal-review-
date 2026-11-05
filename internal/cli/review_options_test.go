package cli

import (
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestParseReviewOptionsExtended(t *testing.T) {
	opts, err := parseReviewOptions([]string{"--only", "slop,secret", "--skip=debug", "--fail-on", "high", "--base", "origin/main", "--format", "sarif"})
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.Only) != 2 || opts.Only[0] != "slop" || opts.Skip[0] != "debug" || opts.FailOn != "high" || opts.Base != "origin/main" || opts.Format != "sarif" {
		t.Fatalf("options = %+v", opts)
	}
	if _, err := parseReviewOptions([]string{"--fail-on", "bogus"}); err == nil {
		t.Fatal("expected error for bad severity")
	}
	if _, err := parseReviewOptions([]string{"--format", "xml"}); err == nil {
		t.Fatal("expected error for bad format")
	}
}

func TestFilterRules(t *testing.T) {
	rules := []review.Rule{
		review.TodoRule{},
		review.DebugRule{},
		review.SlopRule{},
	}
	filtered := filterRules(rules, []string{"code-slop", "todo-marker"}, []string{"debug-leftover"})
	if len(filtered) != 2 {
		t.Fatalf("filtered = %v", filtered)
	}
	for _, r := range filtered {
		if r.Name() == "debug-leftover" {
			t.Fatalf("skipped rule present: %v", filtered)
		}
	}
}
