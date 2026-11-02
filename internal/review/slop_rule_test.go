package review

import "testing"

func TestSlopRuleFindsRedundantBoolean(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,1 +1,3 @@
 package main
+if isValid == true {
+if false != isClosed {
`

	findings := (SlopRule{}).Check(diff)

	if len(findings) != 2 {
		t.Fatalf("Check() returned %d findings, want 2: %+v", len(findings), findings)
	}

	for i, finding := range findings {
		if finding.Rule != "code-slop" {
			t.Errorf("finding[%d].Rule = %q, want %q", i, finding.Rule, "code-slop")
		}
		if finding.Severity != "low" {
			t.Errorf("finding[%d].Severity = %q, want %q", i, finding.Severity, "low")
		}
		if finding.Message != "Redundant boolean comparison" {
			t.Errorf("finding[%d].Message = %q, want %q", i, finding.Message, "Redundant boolean comparison")
		}
		if finding.File != "main.go" {
			t.Errorf("finding[%d].File = %q, want %q", i, finding.File, "main.go")
		}
		if finding.Line != i+2 {
			t.Errorf("finding[%d].Line = %d, want %d", i, finding.Line, i+2)
		}
	}
}

func TestSlopRuleFindsExcessiveNesting(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,1 +1,2 @@
 package main
+				if true {
`

	findings := (SlopRule{}).Check(diff)

	if len(findings) != 1 {
		t.Fatalf("Check() returned %d findings, want 1: %+v", len(findings), findings)
	}

	finding := findings[0]
	if finding.Message != "Excessive indentation (indicates deep nesting)" {
		t.Errorf("finding.Message = %q, want %q", finding.Message, "Excessive indentation (indicates deep nesting)")
	}
}

func TestSlopRuleFindsEmptyBlock(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,1 +1,2 @@
 package main
+if err != nil {}
`

	findings := (SlopRule{}).Check(diff)

	if len(findings) != 1 {
		t.Fatalf("Check() returned %d findings, want 1: %+v", len(findings), findings)
	}

	finding := findings[0]
	if finding.Message != "Empty block" {
		t.Errorf("finding.Message = %q, want %q", finding.Message, "Empty block")
	}
}

func TestSlopRuleIgnoresNormalCode(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,1 +1,2 @@
 package main
+if isValid {
`

	findings := (SlopRule{}).Check(diff)

	if len(findings) != 0 {
		t.Errorf("Check() returned findings for normal code: %+v", findings)
	}
}

func TestSlopRuleName(t *testing.T) {
	if got := (SlopRule{}).Name(); got != "code-slop" {
		t.Errorf("Name() = %q, want %q", got, "code-slop")
	}
}

func TestSlopRuleFindsValueEqualsTrue(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,1 +1,2 @@
 package main
+if value == true {
`
	findings := (SlopRule{}).Check(diff)
	if len(findings) != 1 {
		t.Fatalf("Check() returned %d findings, want 1", len(findings))
	}
}

func TestSlopRuleIgnoresInterface(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,1 +1,2 @@
 package main
+var x interface{}
`
	findings := (SlopRule{}).Check(diff)
	if len(findings) != 0 {
		t.Fatalf("Check() returned %d findings, want 0", len(findings))
	}
}

func TestSlopRuleIgnoresComments(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,1 +1,2 @@
 package main
+// if x == true {
`
	findings := (SlopRule{}).Check(diff)
	if len(findings) != 0 {
		t.Fatalf("Check() returned %d findings, want 0", len(findings))
	}
}

func TestSlopRuleIgnoresStringLiterals(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,1 +1,2 @@
 package main
+fmt.Println("is this == true {}")
`
	findings := (SlopRule{}).Check(diff)
	if len(findings) != 0 {
		t.Fatalf("Check() returned %d findings, want 0", len(findings))
	}
}
