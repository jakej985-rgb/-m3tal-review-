package review

import "testing"

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
	if findingFingerprint(f) != findingFingerprint(f) {
		t.Fatal("fingerprint not stable")
	}
	f2 := f
	f2.Line = 4
	if findingFingerprint(f) == findingFingerprint(f2) {
		t.Fatal("fingerprint ignores line")
	}
}
