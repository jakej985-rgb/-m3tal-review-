package slop_test

import (
	"testing"

	review "github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestCSharpAnalyzerFindsNestingAndBooleanComparison(t *testing.T) {
	source := `class Example { void Run(bool a, bool b, bool c, bool d) {
 if (a) { if (b) { if (c) { if (d == true) { Work(); } } } }
} }`
	repo := stageNonGoSlopSource(t, "main.cs", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.cs", source))
	hasNesting, hasBoolean := false, false
	for _, finding := range findings {
		hasNesting = hasNesting || finding.Message == "Excessive syntax nesting depth (4+ levels)"
		hasBoolean = hasBoolean || finding.Message == "Redundant boolean comparison"
	}
	if !hasNesting || !hasBoolean {
		t.Fatalf("expected nesting and boolean findings, got: %+v", findings)
	}
}

func TestCSharpAnalyzerSkipsVerbatimStringContents(t *testing.T) {
	source := `class Example { void Run() {
    var text = @"text "" and unmatched } inside";
    if (ready) { Work(); }
} }`
	repo := stageNonGoSlopSource(t, "main.cs", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.cs", source))
	for _, finding := range findings {
		if finding.Rule == "code-slop-analysis-error" {
			t.Fatalf("valid C# verbatim string caused analysis failure: %+v", findings)
		}
	}
}

func TestCSharpAnalyzerSkipsRawStringContents(t *testing.T) {
	source := `class Example { void Run() {
	var text = $$"""raw unmatched } inside""";
    if (ready) { Work(); }
} }`
	repo := stageNonGoSlopSource(t, "main.cs", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.cs", source))
	for _, finding := range findings {
		if finding.Rule == "code-slop-analysis-error" {
			t.Fatalf("valid C# raw string caused analysis failure: %+v", findings)
		}
	}
}
