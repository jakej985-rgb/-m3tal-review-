package review

import "testing"

func TestTLSRuleFindsDisabledVerification(t *testing.T) {
	diff := `diff --git a/client.go b/client.go
--- a/client.go
+++ b/client.go
@@ -1,1 +1,4 @@
 package main
+tls.Config{InsecureSkipVerify: true}
+InsecureSkipVerify: true,
+cfg.InsecureSkipVerify = true
`

	findings := (TLSRule{}).Check(diff)

	if len(findings) != 3 {
		t.Fatalf("Check() returned %d findings, want 3: %+v", len(findings), findings)
	}

	for i, finding := range findings {
		if finding.Rule != "insecure-tls-verification" {
			t.Errorf("finding[%d].Rule = %q, want %q", i, finding.Rule, "insecure-tls-verification")
		}
		if finding.Severity != "high" {
			t.Errorf("finding[%d].Severity = %q, want %q", i, finding.Severity, "high")
		}
		if finding.File != "client.go" {
			t.Errorf("finding[%d].File = %q, want %q", i, finding.File, "client.go")
		}
		if finding.Line != i+2 {
			t.Errorf("finding[%d].Line = %d, want %d", i, finding.Line, i+2)
		}
	}
}

func TestTLSRuleIgnoresEnabledVerification(t *testing.T) {
	diff := `diff --git a/client.go b/client.go
--- a/client.go
+++ b/client.go
@@ -1,1 +1,3 @@
 package main
+tls.Config{InsecureSkipVerify: false}
+cfg.InsecureSkipVerify = false
`

	findings := (TLSRule{}).Check(diff)

	if len(findings) != 0 {
		t.Errorf("Check() returned findings when verification is enabled: %+v", findings)
	}
}

func TestTLSRuleName(t *testing.T) {
	if got := (TLSRule{}).Name(); got != "insecure-tls-verification" {
		t.Errorf("Name() = %q, want %q", got, "insecure-tls-verification")
	}
}
