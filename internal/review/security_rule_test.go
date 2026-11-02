package review

import "testing"

func TestSecurityRuleFindsHardcodedCredentials(t *testing.T) {
	diff := `diff --git a/config.go b/config.go
--- a/config.go
+++ b/config.go
@@ -1,1 +1,3 @@
 package main
+password = "supersecretpassword"
+api_key = "abc123456789"
`

	findings := (SecurityRule{}).Check(diff)

	if len(findings) != 2 {
		t.Fatalf("Check() returned %d findings, want 2: %+v", len(findings), findings)
	}

	for i, finding := range findings {
		if finding.Rule != "hardcoded-credential" {
			t.Errorf("finding[%d].Rule = %q, want %q", i, finding.Rule, "hardcoded-credential")
		}
		if finding.Severity != "high" {
			t.Errorf("finding[%d].Severity = %q, want %q", i, finding.Severity, "high")
		}
		if finding.File != "config.go" {
			t.Errorf("finding[%d].File = %q, want %q", i, finding.File, "config.go")
		}
		if finding.Line != i+2 {
			t.Errorf("finding[%d].Line = %d, want %d", i, finding.Line, i+2)
		}
	}
}

func TestSecurityRuleIgnoresPlaceholdersAndUnchangedLines(t *testing.T) {
	diff := `diff --git a/config.go b/config.go
--- a/config.go
+++ b/config.go
@@ -1,2 +1,2 @@
-password = "oldsecretvalue"
+password = "YOUR_API_KEY_HERE"
+token = "changeme"
 secret = "unchangedsecretvalue"
`

	findings := (SecurityRule{}).Check(diff)

	if len(findings) != 0 {
		t.Errorf("Check() returned findings for placeholders or unchanged lines: %+v", findings)
	}
}

func TestSecurityRuleName(t *testing.T) {
	if got := (SecurityRule{}).Name(); got != "hardcoded-credential" {
		t.Errorf("Name() = %q, want %q", got, "hardcoded-credential")
	}
}
