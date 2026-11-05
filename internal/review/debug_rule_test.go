package review

import "testing"

func TestDebugRuleFindsDebugStatements(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,1 +1,4 @@
 package main
+fmt.Println("debug")
+console.log("debug")
+debugger;
`

	findings := (DebugRule{}).Check(diff)

	if len(findings) != 3 {
		t.Fatalf("Check() returned %d findings, want 3: %+v", len(findings), findings)
	}

	want := []struct {
		line    int
		message string
	}{
		{2, "Debug print statement detected"},
		{3, "Console log statement detected"},
		{4, "Debugger statement detected"},
	}

	for i, finding := range findings {
		if finding.Rule != "debug-leftover" {
			t.Errorf("finding[%d].Rule = %q, want %q", i, finding.Rule, "debug-leftover")
		}

		if finding.Severity != "medium" {
			t.Errorf("finding[%d].Severity = %q, want %q", i, finding.Severity, "medium")
		}

		if finding.File != "main.go" {
			t.Errorf("finding[%d].File = %q, want %q", i, finding.File, "main.go")
		}

		if finding.Line != want[i].line {
			t.Errorf("finding[%d].Line = %d, want %d", i, finding.Line, want[i].line)
		}

		if finding.Message != want[i].message {
			t.Errorf("finding[%d].Message = %q, want %q", i, finding.Message, want[i].message)
		}
	}
}

func TestDebugRuleIgnoresUnchangedLines(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,2 +1,2 @@
-fmt.Println("old debug")
+fmt.Sprintf("formatted")
 console.log("existing debug")
`

	findings := (DebugRule{}).Check(diff)

	if len(findings) != 0 {
		t.Errorf("Check() returned findings for unchanged debug statements: %+v", findings)
	}
}

func TestDebugRuleIgnoresCLIOutputAndPatchFiles(t *testing.T) {
	diff := `diff --git a/internal/cli/cli.go b/internal/cli/cli.go
--- a/internal/cli/cli.go
+++ b/internal/cli/cli.go
@@ -0,0 +1 @@
+fmt.Println("M3TAL Review Report")
diff --git a/change.patch b/change.patch
--- /dev/null
+++ b/change.patch
@@ -0,0 +1 @@
+fmt.Println("debug")
`
	if findings := (DebugRule{}).Check(diff); len(findings) != 0 {
		t.Fatalf("findings = %+v; want none for normal CLI output and patch text", findings)
	}
}

func TestDebugRuleName(t *testing.T) {
	if got := (DebugRule{}).Name(); got != "debug-leftover" {
		t.Errorf("Name() = %q, want %q", got, "debug-leftover")
	}
}
