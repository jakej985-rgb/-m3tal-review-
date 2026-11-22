package slop_test

import (
	"testing"

	review "github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestDartAnalyzerFindsNestingAndBooleanComparison(t *testing.T) {
	source := `void run(bool a, bool b, bool c, bool d) {
  if (a) {
    if (b) {
      if (c) {
        if (d == true) {
          work();
        }
      }
    }
  }
}`
	repo := stageNonGoSlopSource(t, "main.dart", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.dart", source))
	hasNesting, hasBoolean := false, false
	for _, finding := range findings {
		hasNesting = hasNesting || finding.Message == "Excessive syntax nesting depth (4+ levels)"
		hasBoolean = hasBoolean || finding.Message == "Redundant boolean comparison"
	}
	if !hasNesting || !hasBoolean {
		t.Fatalf("expected nesting and boolean findings in Dart code, got: %+v", findings)
	}
}
