package slop_test

import (
	"testing"

	review "github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestPythonSyntaxAnalyzerFindsDeepNestingAndBooleanComparison(t *testing.T) {
	source := "def run(a, b, c, d):\n    if a:\n        if b:\n            if c:\n                if d == True:\n                    pass\n"
	repo := stageNonGoSlopSource(t, "main.py", source)
	diff := "diff --git a/main.py b/main.py\n--- a/main.py\n+++ b/main.py\n@@ -4,0 +5,2 @@\n+                if d == True:\n+                    pass\n"
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(diff)
	if len(findings) != 3 {
		t.Fatalf("want nesting, empty pass block, and boolean findings, got %+v", findings)
	}
	if findings[0].Line != 5 || findings[0].Message != "Excessive syntax nesting depth (4+ levels)" || findings[1].Message != "Empty block" || findings[2].Message != "Redundant boolean comparison" {
		t.Fatalf("unexpected Python findings: %+v", findings)
	}
}

func TestPythonSyntaxAnalyzerIgnoresStringsAndComments(t *testing.T) {
	source := "message = \"if a == True:\"\n# if a == True:\n"
	repo := stageNonGoSlopSource(t, "main.py", source)
	diff := "diff --git a/main.py b/main.py\n--- a/main.py\n+++ b/main.py\n@@ -0,0 +1,2 @@\n+message = \"if a == True:\"\n+# if a == True:\n"
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(diff)
	if len(findings) != 0 {
		t.Fatalf("strings/comments produced Python findings: %+v", findings)
	}
}

func TestPythonSyntaxAnalyzerHandlesMultilineAndAsyncHeaders(t *testing.T) {
	source := "async def run(a, b, c, d):\n    if a:\n        if b:\n            if c:\n                async for item in items:\n                    if (\n                        item ==\n                        True\n                    ):\n                        run_one()\n"
	repo := stageNonGoSlopSource(t, "main.py", source)
	diff := "diff --git a/main.py b/main.py\n--- a/main.py\n+++ b/main.py\n@@ -4,3 +4,6 @@\n             if c:\n+                async for item in items:\n                     if (\n+                        item ==\n+                        True\n                     ):\n"
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(diff)
	if len(findings) != 2 {
		t.Fatalf("want async nesting and multiline boolean findings, got %+v", findings)
	}
	if findings[0].Line != 5 || findings[0].Message != "Excessive syntax nesting depth (4+ levels)" || findings[1].Line != 7 || findings[1].Message != "Redundant boolean comparison" {
		t.Fatalf("unexpected multiline Python findings: %+v", findings)
	}
}

func TestPythonSyntaxAnalyzerTreatsElifAsSiblingAndResetsAtNestedFunction(t *testing.T) {
	chain := "def choose(a, b, c, d, e):\n    if a:\n        print(a)\n    elif b:\n        print(b)\n    elif c:\n        print(c)\n    elif d:\n        print(d)\n    elif e:\n        print(e)\n"
	repo := stageNonGoSlopSource(t, "main.py", chain)
	if findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.py", chain)); len(findings) != 0 {
		t.Fatalf("elif chain should remain sibling branches: %+v", findings)
	}

	nested := "if a:\n    if b:\n        if c:\n            def inner():\n                if d:\n                    if e:\n                        if f:\n                            run()\n"
	repo = stageNonGoSlopSource(t, "main.py", nested)
	if findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.py", nested)); len(findings) != 0 {
		t.Fatalf("nested function should reset control-flow depth: %+v", findings)
	}
}

func TestPythonSyntaxAnalyzerReportsIncompleteSuite(t *testing.T) {
	source := "def run():\n"
	repo := stageNonGoSlopSource(t, "main.py", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.py", source))
	if len(findings) != 1 || findings[0].Rule != "code-slop-analysis-error" || findings[0].Severity != "high" {
		t.Fatalf("incomplete Python suite should not pass: %+v", findings)
	}
}

func TestPythonSyntaxAnalyzerCountsMatchNesting(t *testing.T) {
	source := `def run(value):
    match value:
        case 1:
            if ready:
                if useful:
                    if enabled:
                        work()
`
	repo := stageNonGoSlopSource(t, "main.py", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.py", source))
	for _, finding := range findings {
		if finding.Message == "Excessive syntax nesting depth (4+ levels)" && finding.Line == 6 {
			return
		}
	}
	t.Fatalf("expected the fourth nested control to include the match statement: %+v", findings)
}

func TestPythonSyntaxAnalyzerDoesNotTreatIdentifierSuffixAsContinuation(t *testing.T) {
	source := `def run():
    value = command
    if ready:
        if useful:
            if enabled:
                if available:
                    work()
`
	repo := stageNonGoSlopSource(t, "main.py", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.py", source))
	for _, finding := range findings {
		if finding.Message == "Excessive syntax nesting depth (4+ levels)" && finding.Line == 6 {
			return
		}
	}
	t.Fatalf("identifier ending in 'and' swallowed a following control statement: %+v", findings)
}
