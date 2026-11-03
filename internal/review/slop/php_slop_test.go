package slop_test

import (
	"testing"

	review "github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestPHPAnalyzerFindsNestingAndBooleanComparison(t *testing.T) {
	source := `<?php
function run($a, $b, $c, $d) {
 if ($a) { if ($b) { if ($c) { if ($d === true) { work(); } } } }
}`
	repo := stageNonGoSlopSource(t, "main.php", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.php", source))
	hasNesting, hasBoolean := false, false
	for _, finding := range findings {
		hasNesting = hasNesting || finding.Message == "Excessive syntax nesting depth (4+ levels)"
		hasBoolean = hasBoolean || finding.Message == "Redundant boolean comparison"
	}
	if !hasNesting || !hasBoolean {
		t.Fatalf("expected nesting and boolean findings, got: %+v", findings)
	}
}

func TestPHPAnalyzerSupportsAlternateControlSyntaxAndStrictInequality(t *testing.T) {
	source := `<?php
if ($a):
  if ($b):
    if ($c):
      if ($d !== TRUE):
        work();
      endif;
    endif;
  endif;
endif;
`
	repo := stageNonGoSlopSource(t, "main.php", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.php", source))
	hasNesting, hasBoolean := false, false
	for _, finding := range findings {
		hasNesting = hasNesting || finding.Message == "Excessive syntax nesting depth (4+ levels)"
		hasBoolean = hasBoolean || finding.Message == "Redundant boolean comparison"
	}
	if !hasNesting || !hasBoolean {
		t.Fatalf("expected alternate syntax nesting and strict boolean findings, got: %+v", findings)
	}
}

func TestPHPAnalyzerFindsEmptyAlternateControlBlock(t *testing.T) {
	source := "<?php\nif ($ready): endif;\n"
	repo := stageNonGoSlopSource(t, "main.php", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.php", source))
	if len(findings) != 1 || findings[0].Message != "Empty block" {
		t.Fatalf("expected an empty alternate-syntax block finding, got: %+v", findings)
	}
}

func TestPHPAnalyzerFindsEmptyAlternateElseBlock(t *testing.T) {
	source := "<?php\nif ($ready): work(); else: endif;\n"
	repo := stageNonGoSlopSource(t, "main.php", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.php", source))
	if len(findings) != 1 || findings[0].Message != "Empty block" || findings[0].Line != 2 {
		t.Fatalf("expected empty alternate else finding on line 2, got: %+v", findings)
	}
}

func TestPHPAnalyzerSkipsHeredocAndNowdocContents(t *testing.T) {
	source := `<?php
$heredoc = <<<TEXT
quote " and unmatched }
TEXT;
$nowdoc = <<<'RAW'
quote ' and unmatched {
RAW;
if ($ready === true) { work(); }
`
	repo := stageNonGoSlopSource(t, "main.php", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.php", source))
	hasBoolean := false
	for _, finding := range findings {
		if finding.Rule == "code-slop-analysis-error" {
			t.Fatalf("valid PHP heredoc or nowdoc caused analysis failure: %+v", findings)
		}
		hasBoolean = hasBoolean || finding.Message == "Redundant boolean comparison"
	}
	if !hasBoolean {
		t.Fatalf("code following heredoc terminators was not analyzed: %+v", findings)
	}
}
