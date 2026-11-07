package review

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInlineSuppression(t *testing.T) {
	diff := "diff --git a/main.go b/main.go\n--- a/main.go\n+++ b/main.go\n@@ -1,2 +1,3 @@\n package main\n+// m3tal-review: ignore code-slop\n+func f() {}\n"
	findings := []Finding{{Rule: "code-slop", Severity: "low", File: "main.go", Line: 3, Message: "x"}}
	out := ApplyFindingFilters(diff, findings, "/tmp/none", false)
	if len(out) != 0 {
		t.Fatalf("suppressed finding not filtered: %+v", out)
	}
	// Different rule on same line is not suppressed.
	findings[0].Rule = "other-rule"
	out = ApplyFindingFilters(diff, findings, "/tmp/none", false)
	if len(out) != 1 {
		t.Fatalf("wrong rule suppressed: %+v", out)
	}
}

func TestFindingFingerprintStable(t *testing.T) {
	f := Finding{Rule: "r", File: "a.go", Line: 3, Message: "m"}
	fp1 := findingFingerprint(f)
	fp2 := findingFingerprint(f)
	if fp1 != fp2 {
		t.Fatal("fingerprint not stable")
	}
	f2 := f
	f2.Line = 4
	if findingFingerprint(f) == findingFingerprint(f2) {
		t.Fatal("fingerprint ignores line")
	}
}

func TestPerPathPolicyOverride(t *testing.T) {
	dir := t.TempDir()
	policy := `{"paths": {"main.go": {"code-slop": {"severity": "info"}}, "x_test.go": {"code-slop": {"enabled": false}}}}`
	if err := os.WriteFile(filepath.Join(dir, policyFileName), []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	diff := extraDiff("main.go", "package main\n\nfunc f() {}\n") + extraDiff("x_test.go", "package main\n\nfunc g() {}\n")
	findings := []Finding{
		{Rule: "code-slop", Severity: "low", File: "main.go", Line: 3, Message: "m"},
		{Rule: "code-slop", Severity: "low", File: "x_test.go", Line: 3, Message: "m"},
	}
	out := ApplyFindingFilters(diff, findings, dir, true)
	for _, f := range out {
		if f.File == "x_test.go" {
			t.Fatalf("per-path disable failed: %+v", f)
		}
		if f.File == "main.go" && f.Severity != "info" {
			t.Fatalf("per-path severity override failed: got %s", f.Severity)
		}
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 finding after filtering, got %d", len(out))
	}
}
