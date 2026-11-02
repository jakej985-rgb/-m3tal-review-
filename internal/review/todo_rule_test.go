package review

import "testing"

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
