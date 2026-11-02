package review

import "testing"

func TestEngineRunsRules(t *testing.T) {
	engine := NewEngine(TodoRule{})

	diff := `diff --git a/example.go b/example.go
--- a/example.go
+++ b/example.go
@@ -1,1 +1,2 @@
 package main
+// TODO: finish this
`

	findings := engine.Run(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Rule != "todo-marker" {
		t.Errorf("expected todo-marker, got %q", findings[0].Rule)
	}
}

func TestEngineWithNoRules(t *testing.T) {
	engine := NewEngine()

	findings := engine.Run("some diff")

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}