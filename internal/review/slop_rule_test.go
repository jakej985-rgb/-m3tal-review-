package review

import (
	"os"
	"path/filepath"
	"testing"
)

func setupSlopTestRepo(t *testing.T, source string) string {
	t.Helper()
	repoDir := t.TempDir()

	if err := os.WriteFile(
		filepath.Join(repoDir, "go.mod"),
		[]byte("module sloptest\n\ngo 1.23\n"),
		0644,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		filepath.Join(repoDir, "main.go"),
		[]byte(source),
		0644,
	); err != nil {
		t.Fatal(err)
	}

	return repoDir
}

func TestSlopRuleFindsRedundantBoolean(t *testing.T) {
	source := `package main
func main() {
	isValid := false
	isClosed := false
	if isValid == true {
	}
	if false != isClosed {
	}
}`
	repoDir := setupSlopTestRepo(t, source)

	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -3,2 +3,4 @@
	isClosed := false
+	if isValid == true {
+	}
+	if false != isClosed {
+	}
 }`

	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)

	// In AST mode, Empty block will also be found because {} are empty. So expect 4 findings.
	foundRedundantCount := 0
	for _, finding := range findings {
		if finding.Rule != "code-slop" {
			t.Errorf("Rule = %q, want code-slop", finding.Rule)
		}
		if finding.Message == "Redundant boolean comparison" {
			foundRedundantCount++
		}
	}

	if foundRedundantCount != 2 {
		t.Fatalf("expected 2 Redundant boolean comparison findings, got %d", foundRedundantCount)
	}
}

func TestSlopRuleFindsExcessiveNesting(t *testing.T) {
	source := `package main
func main() {
	if true {
		if true {
			if true {
				if true {
					println("nested")
				}
			}
		}
	}
}`
	repoDir := setupSlopTestRepo(t, source)
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -4,4 +4,6 @@
		if true {
			if true {
+				if true {
+					println("nested")
+				}
			}
`
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)

	foundNesting := false
	for _, finding := range findings {
		if finding.Message == "Excessive AST nesting depth (4+ levels)" {
			foundNesting = true
		}
	}
	if !foundNesting {
		t.Fatalf("expected Excessive AST nesting depth finding, got none: %+v", findings)
	}
}

func TestSlopRuleFindsEmptyBlock(t *testing.T) {
	source := `package main
func main() {
	if err != nil {}
}`
	repoDir := setupSlopTestRepo(t, source)
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,2 +1,3 @@
 package main
 func main() {
+	if err != nil {}
 }
`
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)

	foundEmpty := false
	for _, f := range findings {
		if f.Message == "Empty block" {
			foundEmpty = true
		}
	}
	if !foundEmpty {
		t.Fatalf("expected Empty block finding")
	}
}

func TestSlopRuleIgnoresNormalCode(t *testing.T) {
	source := `package main
func main() {
	isValid := false
	if isValid {
		println("valid")
	}
}`
	repoDir := setupSlopTestRepo(t, source)
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -2,2 +2,4 @@
	isValid := false
+	if isValid {
+		println("valid")
+	}
 }`

	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
	if len(findings) != 0 {
		t.Errorf("Check() returned findings for normal code: %+v", findings)
	}
}

func TestSlopRuleName(t *testing.T) {
	if got := (SlopRule{}).Name(); got != "code-slop" {
		t.Errorf("Name() = %q, want %q", got, "code-slop")
	}
}

func TestSlopRuleIgnoresInterface(t *testing.T) {
	source := `package main
var x interface{}`
	repoDir := setupSlopTestRepo(t, source)
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,1 +1,2 @@
 package main
+var x interface{}
`
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
	if len(findings) != 0 {
		t.Fatalf("Check() returned %d findings, want 0", len(findings))
	}
}

func TestSlopRuleIgnoresComments(t *testing.T) {
	source := `package main
// if x == true {}`
	repoDir := setupSlopTestRepo(t, source)
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,1 +1,2 @@
 package main
+// if x == true {}
`
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
	if len(findings) != 0 {
		t.Fatalf("Check() returned %d findings, want 0", len(findings))
	}
}

func TestSlopRuleIgnoresStringLiterals(t *testing.T) {
	source := `package main
func main() {
	println("this contains == true and {}")
}`
	repoDir := setupSlopTestRepo(t, source)
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,2 +1,3 @@
 package main
 func main() {
+	println("this contains == true and {}")
 }`
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
	if len(findings) != 0 {
		t.Fatalf("Check() returned %d findings, want 0", len(findings))
	}
}

func TestSlopRuleDetectsValidFindingsWithStringsOnSameLine(t *testing.T) {
	source := `package main
func main() {
	isValid := false
	if isValid == true { println("valid") }
}`
	repoDir := setupSlopTestRepo(t, source)
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -3,2 +3,3 @@
	isValid := false
+	if isValid == true { println("valid") }
 }`
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
	foundRedundant := false
	for _, f := range findings {
		if f.Message == "Redundant boolean comparison" {
			foundRedundant = true
		}
	}
	if !foundRedundant {
		t.Fatalf("expected Redundant boolean comparison finding, got: %+v", findings)
	}
}
