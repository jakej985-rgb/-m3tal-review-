package slop_test

import (
	"testing"

	review "github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestCppAnalyzerFindsNestingAndBooleanComparison(t *testing.T) {
	source := `void run(bool a, bool b, bool c, bool d) {
 if (a) { if (b) { if (c) { if (d == true) { work(); } } } }
}`
	repo := stageNonGoSlopSource(t, "main.cpp", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.cpp", source))
	hasNesting, hasBoolean := false, false
	for _, finding := range findings {
		hasNesting = hasNesting || finding.Message == "Excessive syntax nesting depth (4+ levels)"
		hasBoolean = hasBoolean || finding.Message == "Redundant boolean comparison"
	}
	if !hasNesting || !hasBoolean {
		t.Fatalf("expected nesting and boolean findings, got: %+v", findings)
	}
}

func TestCppAnalyzerSkipsRawStringContents(t *testing.T) {
	source := `int main() {
    auto text = R"tag(text " and unmatched } inside)tag";
    if (ready) { work(); }
}`
	repo := stageNonGoSlopSource(t, "main.cpp", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.cpp", source))
	for _, finding := range findings {
		if finding.Rule == "code-slop-analysis-error" {
			t.Fatalf("valid C++ raw string caused analysis failure: %+v", findings)
		}
	}
}

func TestCppAnalyzerSkipsConditionalPreprocessorBranches(t *testing.T) {
	source := `void run() {
#if FEATURE_A
    if (a) {
#else
    if (b) {
#endif
        work();
    }
}`
	repo := stageNonGoSlopSource(t, "main.cpp", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.cpp", source))
	for _, finding := range findings {
		if finding.Rule == "code-slop-analysis-error" {
			t.Fatalf("valid conditional compilation branches caused analysis failure: %+v", findings)
		}
	}
}
