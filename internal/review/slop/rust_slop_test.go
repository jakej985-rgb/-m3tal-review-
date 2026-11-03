package slop_test

import (
	"testing"

	review "github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestRustAnalyzerFindsNestingAndBooleanComparison(t *testing.T) {
	source := `fn run(a: bool, b: bool, c: bool, d: bool) {
 if a { if b { if c { if d == true { work(); } } } }
}`
	repo := stageNonGoSlopSource(t, "main.rs", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.rs", source))
	hasNesting, hasBoolean := false, false
	for _, finding := range findings {
		hasNesting = hasNesting || finding.Message == "Excessive syntax nesting depth (4+ levels)"
		hasBoolean = hasBoolean || finding.Message == "Redundant boolean comparison"
	}
	if !hasNesting || !hasBoolean {
		t.Fatalf("expected nesting and boolean findings, got: %+v", findings)
	}
}

func TestRustAnalyzerSkipsRawStringsAndNestedBlockComments(t *testing.T) {
	source := `fn main() {
    let _raw = r##"text " and unmatched } inside"##;
    /* outer /* nested */ still a comment */
    if ready { work(); }
}`
	repo := stageNonGoSlopSource(t, "main.rs", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.rs", source))
	for _, finding := range findings {
		if finding.Rule == "code-slop-analysis-error" {
			t.Fatalf("valid Rust raw string or nested comment caused analysis failure: %+v", findings)
		}
	}
}
