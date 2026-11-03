package review

import "testing"

func TestPermissionsRuleFindsWorldWritableModes(t *testing.T) {
	diff := `diff --git a/files.go b/files.go
--- a/files.go
+++ b/files.go
@@ -1,1 +1,7 @@
 package main
+os.WriteFile("config.json", data, 0777)
+os.Mkdir("uploads", 0o777)
+os.Chmod("config.json", 0777)
+file.Chmod(0o777)
+os.Chmod("config.json", 0o0777)
+os.Chmod("config.json", os.ModePerm)
`

	findings := (PermissionsRule{}).Check(diff)

	if len(findings) != 6 {
		t.Fatalf("Check() returned %d findings, want 6: %+v", len(findings), findings)
	}

	for i, finding := range findings {
		if finding.Rule != "world-writable-file-mode" {
			t.Errorf("finding[%d].Rule = %q, want %q", i, finding.Rule, "world-writable-file-mode")
		}
		if finding.Severity != "high" {
			t.Errorf("finding[%d].Severity = %q, want %q", i, finding.Severity, "high")
		}
		if finding.File != "files.go" {
			t.Errorf("finding[%d].File = %q, want %q", i, finding.File, "files.go")
		}
		if finding.Line != i+2 {
			t.Errorf("finding[%d].Line = %d, want %d", i, finding.Line, i+2)
		}
	}
}

func TestPermissionsRuleIgnoresRestrictiveModes(t *testing.T) {
	diff := `diff --git a/files.go b/files.go
--- a/files.go
+++ b/files.go
@@ -1,1 +1,7 @@
 package main
+os.WriteFile("config.json", data, 0600)
+os.Mkdir("uploads", 0755)
+os.Chmod("config.json", 0600)
+file.Chmod(0644)
+os.Chmod("config.json", 0o0644)
+os.Chmod("config.json", 0644)
`

	findings := (PermissionsRule{}).Check(diff)

	if len(findings) != 0 {
		t.Errorf("Check() returned findings for ordinary permissions: %+v", findings)
	}
}

func TestPermissionsRuleName(t *testing.T) {
	if got := (PermissionsRule{}).Name(); got != "world-writable-file-mode" {
		t.Errorf("Name() = %q, want %q", got, "world-writable-file-mode")
	}
}
