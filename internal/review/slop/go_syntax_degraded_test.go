package slop_test

import (
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestGoSyntaxIncompleteStagedEditVsFatalError(t *testing.T) {
	// 1. Incomplete staged edit: missing closing brace at EOF
	incompleteSource := `package main
func main() {
	if true == true { // unclosed brace at EOF`
	repoInc := setupSlopTestRepo(t, incompleteSource)
	diffInc := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,3 +1,3 @@
 package main
 func main() {
+	if true == true { // unclosed brace at EOF`

	findingsInc := (review.SlopRule{RepositoryRoot: repoInc}).Check(diffInc)
	var foundIncErr bool
	for _, f := range findingsInc {
		if f.Rule == "code-slop-analysis-error" && f.Severity == "high" {
			foundIncErr = true
			if !strings.Contains(f.Message, "Incomplete staged Go edit") {
				t.Errorf("expected message to identify incomplete staged edit, got: %s", f.Message)
			}
			if !strings.Contains(f.Remediation, "--degraded") {
				t.Errorf("expected remediation to mention --degraded, got: %s", f.Remediation)
			}
		}
	}
	if !foundIncErr {
		t.Fatalf("expected code-slop-analysis-error for incomplete staged edit, got: %+v", findingsInc)
	}

	// 2. Fatal syntax error: invalid tokens / illegal syntax not at EOF
	fatalSource := `package main
func 123badFunctionName() {
	return
}`
	repoFatal := setupSlopTestRepo(t, fatalSource)
	diffFatal := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,3 +1,3 @@
 package main
+func 123badFunctionName() {
+	return
+}`

	findingsFatal := (review.SlopRule{RepositoryRoot: repoFatal}).Check(diffFatal)
	var foundFatalErr bool
	for _, f := range findingsFatal {
		if f.Rule == "code-slop-analysis-error" && f.Severity == "high" {
			foundFatalErr = true
			if !strings.Contains(f.Message, "Failed to parse Go code") {
				t.Errorf("expected fatal error message, got: %s", f.Message)
			}
		}
	}
	if !foundFatalErr {
		t.Fatalf("expected code-slop-analysis-error for fatal syntax error, got: %+v", findingsFatal)
	}
}

func TestGoSyntaxFallbackPartialAndChunkInspection(t *testing.T) {
	// A file with two functions:
	// Function 1 has a syntax error (unclosed brace).
	// Function 2 is valid but contains code-slop (redundant boolean comparison).
	mixedSource := `package main

func broken() {
	if true { // missing closing brace

func validHelper(x bool) bool {
	if x == true {
		return true
	}
	return false
}
`
	repoDir := setupSlopTestRepo(t, mixedSource)
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,11 +1,11 @@
 package main

 func broken() {
 	if true { // missing closing brace

+func validHelper(x bool) bool {
+	if x == true {
+		return true
+	}
+	return false
+}`

	// Default non-degraded mode: both code-slop-analysis-error AND chunk-detected slop finding
	findings := (review.SlopRule{RepositoryRoot: repoDir}).Check(diff)
	var hasAnalysisErr, hasSlopFinding bool
	for _, f := range findings {
		if f.Rule == "code-slop-analysis-error" {
			hasAnalysisErr = true
		}
		if f.Rule == "code-slop" && strings.Contains(f.Message, "Redundant boolean comparison") {
			hasSlopFinding = true
		}
	}
	if !hasAnalysisErr {
		t.Errorf("expected analysis error in non-degraded mode")
	}
	if !hasSlopFinding {
		t.Errorf("expected chunk inspection to find redundant boolean comparison in valid function, got findings: %+v", findings)
	}
}

func TestGoSyntaxDegradedRegexMode(t *testing.T) {
	// Incomplete staged edit with redundant boolean comparison
	source := `package main
func main() {
	if true == true { // missing closing brace`
	repoDir := setupSlopTestRepo(t, source)
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,3 +1,3 @@
 package main
 func main() {
+	if true == true { // missing closing brace`

	// Degraded mode enabled:
	// review.SlopRule.Degraded = true
	findings := (review.SlopRule{RepositoryRoot: repoDir, Degraded: true}).Check(diff)

	var hasHighSeverityErr bool
	var hasDegradedInfo bool
	var hasRegexSlop bool

	for _, f := range findings {
		if f.Rule == "code-slop-analysis-error" && f.Severity == "high" {
			hasHighSeverityErr = true
		}
		if f.Rule == "code-slop-degraded" && f.Severity == "info" {
			hasDegradedInfo = true
		}
		if f.Rule == "code-slop" && strings.Contains(f.Message, "Redundant boolean comparison") {
			hasRegexSlop = true
		}
	}

	if hasHighSeverityErr {
		t.Errorf("degraded mode should NOT emit high-severity code-slop-analysis-error")
	}
	if !hasDegradedInfo {
		t.Errorf("degraded mode should emit informational code-slop-degraded finding, got: %+v", findings)
	}
	if !hasRegexSlop {
		t.Errorf("degraded mode should find redundant boolean comparison via regex analysis, got: %+v", findings)
	}
}
