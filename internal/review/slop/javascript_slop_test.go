package slop_test

import (
	"testing"

	review "github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestJavaScriptSyntaxAnalyzerFindsDeepNestingInAddedContext(t *testing.T) {
	source := "if (a) {\n  if (b) {\n    if (c) {\n      if (d) {\n        run();\n      }\n    }\n  }\n}\n"
	repo := stageNonGoSlopSource(t, "main.js", source)
	diff := "diff --git a/main.js b/main.js\n--- a/main.js\n+++ b/main.js\n@@ -3,0 +4,2 @@\n+      if (d) {\n+        run();\n"
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(diff)
	if len(findings) != 1 || findings[0].Message != "Excessive syntax nesting depth (4+ levels)" || findings[0].Line != 4 {
		t.Fatalf("unexpected JavaScript nesting findings: %+v", findings)
	}
}

func TestJavaScriptSyntaxAnalyzerIgnoresRegularExpressionLiterals(t *testing.T) {
	source := "const pattern = /if\\s*\\(x\\)\\s*\\{\\}/;\n"
	repo := stageNonGoSlopSource(t, "main.js", source)
	diff := "diff --git a/main.js b/main.js\n--- a/main.js\n+++ b/main.js\n@@ -0,0 +1,1 @@\n+const pattern = /if\\s*\\(x\\)\\s*\\{\\}/;\n"
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(diff)
	if len(findings) != 0 {
		t.Fatalf("regular expression literal produced findings: %+v", findings)
	}
}

func TestJavaScriptSyntaxAnalyzerScansTemplateExpressionsButNotText(t *testing.T) {
	source := "const message = `text if (x) {} ${ready === true}`;\n"
	repo := stageNonGoSlopSource(t, "main.js", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.js", source))
	if len(findings) != 1 || findings[0].Line != 1 || findings[0].Message != "Redundant boolean comparison" {
		t.Fatalf("unexpected template expression findings: %+v", findings)
	}
}

func TestJavaScriptSyntaxAnalyzerFindsEmptyControlBlock(t *testing.T) {
	source := "function run(ok) {\n  if (ok) {}\n  Promise.resolve().catch((err) => {});\n}\n"
	repo := stageNonGoSlopSource(t, "main.js", source)
	diff := "diff --git a/main.js b/main.js\n--- a/main.js\n+++ b/main.js\n@@ -1,0 +2,1 @@\n+  if (ok) {}\n"
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(diff)
	if len(findings) != 1 || findings[0].Message != "Empty block" || findings[0].Line != 2 {
		t.Fatalf("unexpected JavaScript empty-block findings: %+v", findings)
	}
}

func TestJavaScriptSyntaxAnalyzerReportsUnbalancedStructure(t *testing.T) {
	source := "function broken() {\n  if (ready) {\n    run();\n}\n"
	repo := stageNonGoSlopSource(t, "main.js", source)
	diff := fullSourceDiff("main.js", source)
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(diff)
	if len(findings) != 1 || findings[0].Rule != "code-slop-analysis-error" || findings[0].Severity != "high" {
		t.Fatalf("unbalanced JavaScript should be marked unanalyzable: %+v", findings)
	}
}
