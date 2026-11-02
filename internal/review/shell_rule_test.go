package review

import "testing"

func TestShellRuleFindsRiskyShellExecution(t *testing.T) {
	diff := `diff --git a/runner.go b/runner.go
--- a/runner.go
+++ b/runner.go
@@ -1,1 +1,3 @@
 package main
+exec.Command("sh", "-c", userInput)
+exec.Command("bash", "-c", "echo hello")
`

	findings := (ShellRule{}).Check(diff)

	if len(findings) != 2 {
		t.Fatalf("Check() returned %d findings, want 2: %+v", len(findings), findings)
	}

	for i, finding := range findings {
		if finding.Rule != "risky-shell-execution" {
			t.Errorf("finding[%d].Rule = %q, want %q", i, finding.Rule, "risky-shell-execution")
		}
		if finding.Severity != "high" {
			t.Errorf("finding[%d].Severity = %q, want %q", i, finding.Severity, "high")
		}
		if finding.File != "runner.go" {
			t.Errorf("finding[%d].File = %q, want %q", i, finding.File, "runner.go")
		}
		if finding.Line != i+2 {
			t.Errorf("finding[%d].Line = %d, want %d", i, finding.Line, i+2)
		}
	}
}

func TestShellRuleIgnoresNormalCommandExecution(t *testing.T) {
	diff := `diff --git a/runner.go b/runner.go
--- a/runner.go
+++ b/runner.go
@@ -1,1 +1,2 @@
 package main
+exec.Command("git", "status")
`

	findings := (ShellRule{}).Check(diff)

	if len(findings) != 0 {
		t.Errorf("Check() returned findings for normal command execution: %+v", findings)
	}
}

func TestShellRuleName(t *testing.T) {
	if got := (ShellRule{}).Name(); got != "risky-shell-execution" {
		t.Errorf("Name() = %q, want %q", got, "risky-shell-execution")
	}
}
