package slop_test

import (
	"testing"

	review "github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestJavaAnalyzerFindsNestingAndBooleanComparison(t *testing.T) {
	source := `class Example { void run(boolean a, boolean b, boolean c, boolean d) {
 if (a) { if (b) { if (c) { if (d == true) { work(); } } } }
} }`
	repo := stageNonGoSlopSource(t, "main.java", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.java", source))
	hasNesting, hasBoolean := false, false
	for _, finding := range findings {
		hasNesting = hasNesting || finding.Message == "Excessive syntax nesting depth (4+ levels)"
		hasBoolean = hasBoolean || finding.Message == "Redundant boolean comparison"
	}
	if !hasNesting || !hasBoolean {
		t.Fatalf("expected nesting and boolean findings, got: %+v", findings)
	}
}

func TestJavaAnalyzerFindsParenthesizedBooleanComparisons(t *testing.T) {
	source := `class Example {
    boolean first = ready == (true);
    boolean second = ((false)) == ready;
}`
	repo := stageNonGoSlopSource(t, "main.java", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.java", source))
	count := 0
	for _, finding := range findings {
		if finding.Message == "Redundant boolean comparison" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("expected two parenthesized boolean findings, got: %+v", findings)
	}
}
