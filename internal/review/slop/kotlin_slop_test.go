package slop_test

import (
	"testing"

	review "github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestKotlinAnalyzerFindsNestingAndBooleanComparison(t *testing.T) {
	source := `fun run(a: Boolean, b: Boolean, c: Boolean, d: Boolean) {
 if (a) { if (b) { if (c) { if (d == true) { work() } } } }
}`
	repo := stageNonGoSlopSource(t, "main.kt", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.kt", source))
	hasNesting, hasBoolean := false, false
	for _, finding := range findings {
		hasNesting = hasNesting || finding.Message == "Excessive syntax nesting depth (4+ levels)"
		hasBoolean = hasBoolean || finding.Message == "Redundant boolean comparison"
	}
	if !hasNesting || !hasBoolean {
		t.Fatalf("expected nesting and boolean findings, got: %+v", findings)
	}
}

func TestKotlinAnalyzerFindsStrictBooleanInequality(t *testing.T) {
	source := "fun run(value: Boolean) { if (value !== false) { work() } }\n"
	repo := stageNonGoSlopSource(t, "main.kt", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.kt", source))
	if len(findings) != 1 || findings[0].Message != "Redundant boolean comparison" {
		t.Fatalf("expected strict boolean inequality finding, got: %+v", findings)
	}
}
