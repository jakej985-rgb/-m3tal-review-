package review

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
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

	cmd := exec.Command("git", "init")
	cmd.Dir = repoDir
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}

	cmd = exec.Command("git", "add", "main.go")
	cmd.Dir = repoDir
	if err := cmd.Run(); err != nil {
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

func TestSlopRuleDeletedFile(t *testing.T) {
	repoDir := setupSlopTestRepo(t, "package main")
	diff := `diff --git a/deleted.go b/deleted.go
--- a/deleted.go
+++ /dev/null
@@ -1,2 +0,0 @@
-package main
-func empty() {}
`
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for deleted file, got %d", len(findings))
	}
}

func TestSlopRuleWorkingTreeDifference(t *testing.T) {
	source := "package main\nfunc main() {\n\tif true == false {}\n}"
	repoDir := setupSlopTestRepo(t, source)

	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\nfunc main() {}"), 0644); err != nil {
		t.Fatal(err)
	}

	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -2,2 +2,3 @@
 func main() {
+	if true == false {}
 }`
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)

	found := false
	for _, f := range findings {
		if f.Message == "Redundant boolean comparison" {
			found = true
		}
	}

	if !found {
		t.Fatalf("expected finding from staged content even if working tree is different")
	}
}

func TestSlopRuleNestingDepthBoundaries(t *testing.T) {
	source := `package main
func main() {
	if true { // 2 (func is 1)
		if true { // 3 (Should NOT trigger)
		}
	}
}`
	repoDir := setupSlopTestRepo(t, source)
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -2,4 +2,5 @@
	if true { // 2 (func is 1)
+		if true { // 3 (Should NOT trigger)
+		}
	}
 }`
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
	for _, f := range findings {
		if f.Message == "Excessive AST nesting depth (4+ levels)" {
			t.Fatalf("expected NO excessive nesting finding for depth 3, got %+v", findings)
		}
	}
}

func TestSlopRuleNestingDepth5(t *testing.T) {
	source := `package main
func main() {
	if true { // 1
		if true { // 2
			if true { // 3
				if true { // 4
					if true { // 5 (Should trigger)
					}
				}
			}
		}
	}
}`
	repoDir := setupSlopTestRepo(t, source)
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -5,4 +5,5 @@
			if true { // 3
				if true { // 4
+					if true { // 5 (Should trigger)
+					}
				}
`
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
	found := false
	for _, f := range findings {
		if f.Message == "Excessive AST nesting depth (4+ levels)" && f.Line == 7 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected excessive nesting finding for depth 5 at line 7, got %+v", findings)
	}
}

func TestSlopRuleSiblingDepthNotInherited(t *testing.T) {
	source := `package main
func main() { // 1
	if true { // 2
		if true { // 3
		}
	}
	if true { // 2
		if true { // 3
		}
	}
}`
	repoDir := setupSlopTestRepo(t, source)
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -6,4 +6,5 @@
	}
	if true { // 2
+		if true { // 3
+		}
	}
 }`
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
	for _, f := range findings {
		if f.Message == "Excessive AST nesting depth (4+ levels)" {
			t.Fatalf("expected NO excessive nesting finding for depth 3, got %+v", findings)
		}
	}
}

func TestSlopRuleNoDuplicateFindings(t *testing.T) {
	source := `package main
func main() {
	if true == true {}
}`
	repoDir := setupSlopTestRepo(t, source)
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -2,2 +2,3 @@
 func main() {
+	if true == true {}
 }`
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)

	// This has an empty block AND a redundant boolean comparison on the exact same line!
	// It should return exactly two findings, one for each rule, no duplicates!
	if len(findings) != 2 {
		t.Fatalf("expected exactly 2 findings, got %d: %+v", len(findings), findings)
	}

	foundEmpty := false
	foundRedundant := false
	for _, f := range findings {
		if f.Message == "Empty block" {
			if foundEmpty {
				t.Fatalf("Duplicate Empty block finding!")
			}
			foundEmpty = true
		}
		if f.Message == "Redundant boolean comparison" {
			if foundRedundant {
				t.Fatalf("Duplicate Redundant boolean comparison finding!")
			}
			foundRedundant = true
		}
	}
}

func TestSlopRuleAnalysisErrorOnInvalidSyntax(t *testing.T) {
	source := `package main
func main() {
	if true == true { // Missing closing brace`
	repoDir := setupSlopTestRepo(t, source)
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -2,2 +2,3 @@
 func main() {
+	if true == true { // Missing closing brace`
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)

	foundError := false
	for _, f := range findings {
		if f.Rule == "code-slop-analysis-error" && f.Severity == "high" {
			foundError = true
		}
	}
	if !foundError {
		t.Fatalf("expected code-slop-analysis-error finding for invalid syntax, got: %+v", findings)
	}
}

func TestSlopRuleAnalysisErrorOnMissingFile(t *testing.T) {
	repoDir := setupSlopTestRepo(t, "package main")

	// Create a diff for a file that isn't staged
	diff := `diff --git a/missing.go b/missing.go
--- a/missing.go
+++ b/missing.go
@@ -1,2 +1,3 @@
 package main
+func missing() {}`
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)

	foundError := false
	for _, f := range findings {
		if f.Rule == "code-slop-analysis-error" && f.Severity == "high" {
			foundError = true
		}
	}
	if !foundError {
		t.Fatalf("expected code-slop-analysis-error finding for missing file, got: %+v", findings)
	}
}

func TestSlopRuleRealGitStagedDeletion(t *testing.T) {
	repoDir := t.TempDir()

	runCmd := func(args ...string) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = repoDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("command %v failed: %v\noutput: %s", args, err, out)
		}
	}

	runCmd("git", "init")
	runCmd("git", "config", "user.name", "test")
	runCmd("git", "config", "user.email", "test@test.com")

	filePath := filepath.Join(repoDir, "to_delete.go")
	if err := os.WriteFile(filePath, []byte("package main\n\nfunc unused() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	runCmd("git", "add", "to_delete.go")
	runCmd("git", "commit", "-m", "add file to delete")

	runCmd("git", "rm", "to_delete.go")

	diff, err := git.StagedDiff(repoDir)
	if err != nil {
		t.Fatalf("git.StagedDiff failed: %v", err)
	}

	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
	for _, f := range findings {
		if f.Rule == "code-slop-analysis-error" {
			t.Fatalf("unexpected analysis error for deleted file: %+v", f)
		}
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for staged deletion, got %d: %+v", len(findings), findings)
	}
}

func TestSlopRuleRealGitStagedRename(t *testing.T) {
	repoDir := t.TempDir()

	runCmd := func(args ...string) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = repoDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("command %v failed: %v\noutput: %s", args, err, out)
		}
	}

	runCmd("git", "init")
	runCmd("git", "config", "user.name", "test")
	runCmd("git", "config", "user.email", "test@test.com")

	oldPath := filepath.Join(repoDir, "old.go")
	if err := os.WriteFile(oldPath, []byte("package main\n\nfunc hello() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	runCmd("git", "add", "old.go")
	runCmd("git", "commit", "-m", "initial commit")

	runCmd("git", "mv", "old.go", "new.go")

	newPath := filepath.Join(repoDir, "new.go")
	if err := os.WriteFile(newPath, []byte("package main\n\nfunc hello() {\n\tif true == true {}\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCmd("git", "add", "new.go")

	diff, err := git.StagedDiff(repoDir)
	if err != nil {
		t.Fatalf("git.StagedDiff failed: %v", err)
	}

	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
	for _, f := range findings {
		if f.File != "new.go" {
			t.Errorf("Finding file = %q, want %q", f.File, "new.go")
		}
	}

	seen := make(map[string]bool)
	for _, f := range findings {
		key := f.Message
		if seen[key] {
			t.Fatalf("duplicate finding detected for rename: %+v", f)
		}
		seen[key] = true
	}
}

func TestSlopRuleRealGitMultipleHunks(t *testing.T) {
	repoDir := t.TempDir()

	runCmd := func(args ...string) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = repoDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("command %v failed: %v\noutput: %s", args, err, out)
		}
	}

	runCmd("git", "init")
	runCmd("git", "config", "user.name", "test")
	runCmd("git", "config", "user.email", "test@test.com")

	filePath := filepath.Join(repoDir, "multi.go")
	initialContent := `package main

func funcOne() {
	println("1")
}

func funcTwo() {
	println("2")
}

func funcThree() {
	println("3")
}
`
	if err := os.WriteFile(filePath, []byte(initialContent), 0644); err != nil {
		t.Fatal(err)
	}

	runCmd("git", "add", "multi.go")
	runCmd("git", "commit", "-m", "initial commit")

	modifiedContent := `package main

func funcOne() {
	if true == false {}
	println("1")
}

func funcTwo() {
	println("2")
}

func funcThree() {
	if false == true {}
	println("3")
}
`
	if err := os.WriteFile(filePath, []byte(modifiedContent), 0644); err != nil {
		t.Fatal(err)
	}
	runCmd("git", "add", "multi.go")

	diff, err := git.StagedDiff(repoDir)
	if err != nil {
		t.Fatalf("git.StagedDiff failed: %v", err)
	}

	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
	redundantCount := 0
	for _, f := range findings {
		if f.Message == "Redundant boolean comparison" {
			redundantCount++
		}
	}

	if redundantCount != 2 {
		t.Fatalf("expected 2 redundant boolean comparison findings across multiple hunks, got %d: %+v", redundantCount, findings)
	}
}

func TestSlopRuleSimilarFindingsInSeparateFiles(t *testing.T) {
	repoDir := t.TempDir()

	runCmd := func(args ...string) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = repoDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("command %v failed: %v\noutput: %s", args, err, out)
		}
	}

	runCmd("git", "init")
	runCmd("git", "config", "user.name", "test")
	runCmd("git", "config", "user.email", "test@test.com")

	fileA := filepath.Join(repoDir, "a.go")
	if err := os.WriteFile(fileA, []byte("package main\n\nfunc checkA() {\n\tif true == true {}\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	fileB := filepath.Join(repoDir, "b.go")
	if err := os.WriteFile(fileB, []byte("package main\n\nfunc checkB() {\n\tif false == false {}\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	runCmd("git", "add", "a.go", "b.go")

	diff, err := git.StagedDiff(repoDir)
	if err != nil {
		t.Fatalf("git.StagedDiff failed: %v", err)
	}

	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)

	foundA := false
	foundB := false
	for _, f := range findings {
		if f.File == "a.go" && f.Message == "Redundant boolean comparison" {
			foundA = true
		}
		if f.File == "b.go" && f.Message == "Redundant boolean comparison" {
			foundB = true
		}
	}

	if !foundA || !foundB {
		t.Fatalf("expected findings for both a.go and b.go, got: %+v", findings)
	}
}

func TestSlopRuleStableDeterministicOrder(t *testing.T) {
	repoDir := t.TempDir()

	runCmd := func(args ...string) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = repoDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("command %v failed: %v\noutput: %s", args, err, out)
		}
	}

	runCmd("git", "init")
	runCmd("git", "config", "user.name", "test")
	runCmd("git", "config", "user.email", "test@test.com")

	code := `package main

func first() {
	if true == true {}
}

func second() {
	if false == false {}
}
`
	if err := os.WriteFile(filepath.Join(repoDir, "order.go"), []byte(code), 0644); err != nil {
		t.Fatal(err)
	}
	runCmd("git", "add", "order.go")

	diff, err := git.StagedDiff(repoDir)
	if err != nil {
		t.Fatalf("git.StagedDiff failed: %v", err)
	}

	runs := 5
	var firstRunFindings []Finding
	for i := 0; i < runs; i++ {
		findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
		if i == 0 {
			firstRunFindings = findings
		} else {
			if len(findings) != len(firstRunFindings) {
				t.Fatalf("run %d produced %d findings, expected %d", i, len(findings), len(firstRunFindings))
			}
			for j := range findings {
				if findings[j].Line != firstRunFindings[j].Line || findings[j].Message != firstRunFindings[j].Message {
					t.Fatalf("run %d finding %d differs: %+v vs %+v", i, j, findings[j], firstRunFindings[j])
				}
			}
		}
	}
}

func TestSlopRuleControlFlowNesting4Levels(t *testing.T) {
	source := `package main
func main() {
	if true {
		for i := 0; i < 10; i++ {
			if i > 2 {
				for j := 0; j < 5; j++ {
					println(j)
				}
			}
		}
	}
}`
	repoDir := setupSlopTestRepo(t, source)
	diff, err := git.StagedDiff(repoDir)
	if err != nil {
		t.Fatalf("git.StagedDiff failed: %v", err)
	}
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
	foundNesting := false
	for _, f := range findings {
		if f.Message == "Excessive AST nesting depth (4+ levels)" {
			foundNesting = true
		}
	}
	if !foundNesting {
		t.Fatalf("expected Excessive AST nesting depth finding, got: %+v", findings)
	}
}

func TestSlopRuleControlFlowNesting3Levels(t *testing.T) {
	source := `package main
func main() {
	if true {
		for i := 0; i < 10; i++ {
			if i > 2 {
				println(i)
			}
		}
	}
}`
	repoDir := setupSlopTestRepo(t, source)
	diff, err := git.StagedDiff(repoDir)
	if err != nil {
		t.Fatalf("git.StagedDiff failed: %v", err)
	}
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
	for _, f := range findings {
		if f.Message == "Excessive AST nesting depth (4+ levels)" {
			t.Fatalf("did not expect nesting finding for 3 levels, got: %+v", f)
		}
	}
}

func TestSlopRuleControlFlowSequentialSiblingIfs(t *testing.T) {
	source := `package main
func main() {
	if true {
		println(1)
	}
	if true {
		println(2)
	}
	if true {
		println(3)
	}
	if true {
		println(4)
	}
	if true {
		println(5)
	}
}`
	repoDir := setupSlopTestRepo(t, source)
	diff, err := git.StagedDiff(repoDir)
	if err != nil {
		t.Fatalf("git.StagedDiff failed: %v", err)
	}
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
	for _, f := range findings {
		if f.Message == "Excessive AST nesting depth (4+ levels)" {
			t.Fatalf("did not expect nesting finding for sequential sibling ifs, got: %+v", f)
		}
	}
}

func TestSlopRuleControlFlowNestedLoopsAndSwitches(t *testing.T) {
	source := `package main
func test() {
	ch := make(chan int, 1)
	for i := 0; i < 10; i++ {
		switch i {
		case 1:
			for j := 0; j < 5; j++ {
				select {
				case ch <- j:
					println(j)
				default:
				}
			}
		}
	}
}`
	repoDir := setupSlopTestRepo(t, source)
	diff, err := git.StagedDiff(repoDir)
	if err != nil {
		t.Fatalf("git.StagedDiff failed: %v", err)
	}
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
	foundNesting := false
	for _, f := range findings {
		if f.Message == "Excessive AST nesting depth (4+ levels)" {
			foundNesting = true
		}
	}
	if !foundNesting {
		t.Fatalf("expected Excessive AST nesting depth finding for nested loop/switch/loop/select, got: %+v", findings)
	}
}

func TestSlopRuleControlFlowMultipleFunctions(t *testing.T) {
	source := `package main

func first() {
	if true {
		for i := 0; i < 10; i++ {
			if i > 2 {
				println(i)
			}
		}
	}
}

func second() {
	if true {
		for j := 0; j < 5; j++ {
			if j > 1 {
				println(j)
			}
		}
	}
}
`
	repoDir := setupSlopTestRepo(t, source)
	diff, err := git.StagedDiff(repoDir)
	if err != nil {
		t.Fatalf("git.StagedDiff failed: %v", err)
	}
	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)
	for _, f := range findings {
		if f.Message == "Excessive AST nesting depth (4+ levels)" {
			t.Fatalf("nesting depth should reset per function; neither has 4 levels, got: %+v", f)
		}
	}
}

func TestSlopRuleRealRepoWithSpacesInFilename(t *testing.T) {
	repoDir := t.TempDir()

	runCmd := func(args ...string) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = repoDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("command %v failed: %v\noutput: %s", args, err, out)
		}
	}

	runCmd("git", "init")
	runCmd("git", "config", "user.name", "test")
	runCmd("git", "config", "user.email", "test@test.com")

	subDir := filepath.Join(repoDir, "my space dir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	src := `package main
func test() {
	if true == false {
		println("oops")
	}
}
`
	filePath := filepath.Join(subDir, "my file.go")
	if err := os.WriteFile(filePath, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	runCmd("git", "add", "my space dir/my file.go")

	diff, err := git.StagedDiff(repoDir)
	if err != nil {
		t.Fatalf("git.StagedDiff failed: %v", err)
	}

	findings := (SlopRule{RepositoryRoot: repoDir}).Check(diff)

	foundRedundant := false
	for _, f := range findings {
		if f.Rule == "code-slop-analysis-error" {
			t.Fatalf("unexpected analysis error for path with spaces: %+v", f)
		}
		if f.Message == "Redundant boolean comparison" {
			foundRedundant = true
			if f.File != "my space dir/my file.go" {
				t.Errorf("expected File = 'my space dir/my file.go', got %q", f.File)
			}
		}
	}

	if !foundRedundant {
		t.Fatalf("expected Redundant boolean comparison finding, got: %+v", findings)
	}
}
