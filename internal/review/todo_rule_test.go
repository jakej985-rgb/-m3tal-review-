package review

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTodoRuleFindsAddedTODO(t *testing.T) {
	diff := `diff --git a/example.go b/example.go
--- a/example.go
+++ b/example.go
@@ -1,2 +1,3 @@
 package main
+// TODO: finish this function
 func main() {}
`

	rule := TodoRule{}
	findings := rule.Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Rule != "todo-marker" {
		t.Errorf("expected rule todo-marker, got %q", findings[0].Rule)
	}

	if findings[0].Severity != "low" {
		t.Errorf("expected severity low, got %q", findings[0].Severity)
	}
}

func TestTodoRuleIgnoresUnchangedTODO(t *testing.T) {
	diff := `diff --git a/example.go b/example.go
--- a/example.go
+++ b/example.go
@@ -1,2 +1,2 @@
 // TODO: existing work
 package main
`

	rule := TodoRule{}
	findings := rule.Check(diff)

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestTodoRuleIgnoresDiffHeader(t *testing.T) {
	diff := `diff --git a/TODO.md b/TODO.md
--- a/TODO.md
+++ b/TODO.md
@@ -0,0 +1 @@
+# TODO list
`

	rule := TodoRule{}
	findings := rule.Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for added TODO content, got %d", len(findings))
	}
}

func TestTodoRuleIgnoresFixtureStringsAndNonSourceArtifacts(t *testing.T) {
	diff := `diff --git a/example_test.go b/example_test.go
--- a/example_test.go
+++ b/example_test.go
@@ -0,0 +1,2 @@
+fixture := "// TODO: this is test data"
+// TODO: this is a real comment
diff --git a/example.patch b/example.patch
--- /dev/null
+++ b/example.patch
@@ -0,0 +1 @@
+// TODO: patch content is not source
`
	findings := (TodoRule{}).Check(diff)
	if len(findings) != 1 || findings[0].File != "example_test.go" || findings[0].Line != 2 {
		t.Fatalf("findings = %+v; want only the actual source comment", findings)
	}
}

func TestTodoRuleIgnoresCommentLikeTextInsideGoRawString(t *testing.T) {
	root := t.TempDir()
	source := "package example\nfunc TestExample() {\n\tfixture := `\n // TODO: fixture content\n `\n}\n"
	if err := os.WriteFile(filepath.Join(root, "example_test.go"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	diff := `diff --git a/example_test.go b/example_test.go
--- a/example_test.go
+++ b/example_test.go
@@ -0,0 +1,6 @@
+package example
+func TestExample() {
+\tfixture := ` + "`" + `
+ // TODO: fixture content
+ ` + "`" + `
+}
`
	findings := (TodoRule{RepositoryRoot: root, WorkingTree: true}).Check(diff)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v; want raw-string fixture text ignored", findings)
	}
}

func TestTodoRuleRequiresWholeMarkerWord(t *testing.T) {
	diff := `diff --git a/example.go b/example.go
--- a/example.go
+++ b/example.go
@@ -0,0 +1,2 @@
+// Masked values such as "xxxxxxxx" or "********".
+// FIXME: handle this edge case
`
	findings := (TodoRule{}).Check(diff)
	if len(findings) != 1 || findings[0].Line != 2 {
		t.Fatalf("findings = %+v; want only the standalone FIXME marker", findings)
	}
}

func TestOffsetInCommentResetsAfterLineComment(t *testing.T) {
	source := "// prior comment\ncase review.TodoRule:\n// TODO: real marker\nvar value = \"// TODO in string\"\n"
	codeOffset := strings.Index(source, "TodoRule")
	commentOffset := strings.Index(source, "TODO: real")
	stringOffset := strings.LastIndex(source, "TODO in string")
	if offsetInComment("example.go", source, codeOffset) {
		t.Fatal("code after an earlier comment was classified as a comment")
	}
	if !offsetInComment("example.go", source, commentOffset) {
		t.Fatal("TODO in a line comment was not classified as a comment")
	}
	if offsetInComment("example.go", source, stringOffset) {
		t.Fatal("comment-like text inside a string was classified as a comment")
	}
}
