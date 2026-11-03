package slop_test

import (
	"testing"

	review "github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestSwiftAnalyzerFindsNestingAndBooleanComparison(t *testing.T) {
	source := `func run(_ a: Bool, _ b: Bool, _ c: Bool, _ d: Bool) {
 if a { if b { if c { if d == true { work() } } } }
}`
	repo := stageNonGoSlopSource(t, "main.swift", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.swift", source))
	hasNesting, hasBoolean := false, false
	for _, finding := range findings {
		hasNesting = hasNesting || finding.Message == "Excessive syntax nesting depth (4+ levels)"
		hasBoolean = hasBoolean || finding.Message == "Redundant boolean comparison"
	}
	if !hasNesting || !hasBoolean {
		t.Fatalf("expected nesting and boolean findings, got: %+v", findings)
	}
}

func TestSwiftAnalyzerSkipsRawStringContents(t *testing.T) {
	source := `let text = ##"raw " quote and unmatched } inside"##
if ready { work() }
`
	repo := stageNonGoSlopSource(t, "main.swift", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.swift", source))
	for _, finding := range findings {
		if finding.Rule == "code-slop-analysis-error" {
			t.Fatalf("valid Swift raw string caused analysis failure: %+v", findings)
		}
	}
}

func TestSwiftAnalyzerSelectsOneConditionalCompilationBranch(t *testing.T) {
	source := `#if os(Linux)
if linuxReady {
#else
if otherPlatformReady {
#endif
    work()
}
`
	repo := stageNonGoSlopSource(t, "main.swift", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.swift", source))
	for _, finding := range findings {
		if finding.Rule == "code-slop-analysis-error" {
			t.Fatalf("valid Swift conditional compilation caused analysis failure: %+v", findings)
		}
	}
}
