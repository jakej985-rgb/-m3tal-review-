package review

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestValidateCommitSHA(t *testing.T) {
	validSHA := "0123456789abcdef0123456789abcdef01234567"
	if err := ValidateCommitSHA(validSHA); err != nil {
		t.Fatalf("expected valid SHA to pass, got: %v", err)
	}

	shortSHA := "0123456"
	if err := ValidateCommitSHA(shortSHA); err == nil {
		t.Fatal("expected abbreviated SHA to fail")
	} else if !strings.Contains(err.Error(), "abbreviated prefixes are rejected") {
		t.Fatalf("unexpected error message: %v", err)
	}

	nonHex := "0123456789abcdef0123456789abcdef0123456z"
	if err := ValidateCommitSHA(nonHex); err == nil {
		t.Fatal("expected non-hex SHA to fail")
	}

	empty := ""
	if err := ValidateCommitSHA(empty); err == nil {
		t.Fatal("expected empty SHA to fail")
	}
}

func TestReportAttestationVerification(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	report := Report{
		Repository:  "https://github.com/org/repo",
		CommitSHA:   sha,
		DiffHash:    "diffhash123",
		ToolVersion: "v1.0.0",
		Passed:      true,
		Timestamp:   time.Now().UTC(),
	}

	att, err := GenerateAttestation(&report, "snap123")
	if err != nil {
		t.Fatalf("GenerateAttestation failed: %v", err)
	}
	report.Attestation = &att

	// Valid verification
	if err := VerifyAttestation(report, "https://github.com/org/repo", sha, "diffhash123", "snap123", 1*time.Hour); err != nil {
		t.Fatalf("VerifyAttestation failed on valid report: %v", err)
	}

	// Rejects tampered passed status
	tampered := report
	tampered.Passed = false
	if err := VerifyAttestation(tampered, "https://github.com/org/repo", sha, "diffhash123", "snap123", 1*time.Hour); err == nil {
		t.Fatal("expected tampered passed status to fail verification")
	}

	// Rejects tampered signature
	tamperedSig := report
	badAtt := *tamperedSig.Attestation
	badAtt.Signature = "badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb"
	tamperedSig.Attestation = &badAtt
	if err := VerifyAttestation(tamperedSig, "https://github.com/org/repo", sha, "diffhash123", "snap123", 1*time.Hour); err == nil {
		t.Fatal("expected bad signature to fail verification")
	}

	// Rejects wrong repository
	if err := VerifyAttestation(report, "https://github.com/other/repo", sha, "diffhash123", "snap123", 1*time.Hour); err == nil {
		t.Fatal("expected wrong repository to fail verification")
	}

	// Rejects abbreviated SHA (#115)
	if err := VerifyAttestation(report, "https://github.com/org/repo", "0123456", "diffhash123", "snap123", 1*time.Hour); err == nil {
		t.Fatal("expected abbreviated SHA to fail verification")
	}

	// Rejects mismatched commit SHA
	wrongSHA := "fedcba9876543210fedcba9876543210fedcba98"
	if err := VerifyAttestation(report, "https://github.com/org/repo", wrongSHA, "diffhash123", "snap123", 1*time.Hour); err == nil {
		t.Fatal("expected mismatched commit SHA to fail verification")
	}

	// Rejects stale report
	staleAtt := *report.Attestation
	staleAtt.Timestamp = time.Now().Add(-48 * time.Hour)
	staleReport := report
	staleReport.Attestation = &staleAtt
	if err := VerifyAttestation(staleReport, "https://github.com/org/repo", sha, "diffhash123", "snap123", 24*time.Hour); err == nil {
		t.Fatal("expected stale report to fail verification")
	}
}

func TestVerifyRemediation(t *testing.T) {
	finding := Finding{
		ID:       "test-id-1",
		Rule:     "timing-unsafe-compare",
		File:     "auth.go",
		Line:     3,
		Severity: "medium",
	}

	vulnerableCode := "package auth\nfunc Verify(token, expected string) bool {\n\treturn token == expected\n}\n"
	vulnDiff := extraDiff("auth.go", vulnerableCode)

	rules := ExtraRules("/tmp/nonexistent-root")

	// 1. Unchanged diff -> unfixed
	resUnchanged := VerifyRemediation(finding, vulnDiff, vulnDiff, rules, nil)
	if resUnchanged.Status != "unfixed" {
		t.Fatalf("expected status 'unfixed', got %q", resUnchanged.Status)
	}

	// 2. Changed code but vulnerability remains -> unfixed
	stillVulnCode := "package auth\n// changed comment\nfunc Verify(token, expected string) bool {\n\treturn token == expected\n}\n"
	stillVulnDiff := extraDiff("auth.go", stillVulnCode)
	resStillVuln := VerifyRemediation(finding, vulnDiff, stillVulnDiff, rules, nil)
	if resStillVuln.Status != "unfixed" {
		t.Fatalf("expected status 'unfixed', got %q", resStillVuln.Status)
	}

	// 3. Repair introduces a new blocking defect (hardcoded secret) -> new_blocking_findings
	newBugCode := "package auth\nimport \"crypto/subtle\"\nconst JWT_SECRET = \"supersecret1234567890\"\nfunc Verify(token, expected string) bool {\n\treturn subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1\n}\n"
	newBugDiff := extraDiff("auth.go", newBugCode)
	resNewBug := VerifyRemediation(finding, vulnDiff, newBugDiff, rules, nil)
	if resNewBug.Status != "new_blocking_findings" {
		t.Fatalf("expected status 'new_blocking_findings', got %q (%s)", resNewBug.Status, resNewBug.Explanation)
	}

	// 4. Failing regression tests -> regression_failure
	cleanCode := "package auth\nimport \"crypto/subtle\"\nfunc Verify(token, expected string) bool {\n\treturn subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1\n}\n"
	cleanDiff := extraDiff("auth.go", cleanCode)
	resTestFail := VerifyRemediation(finding, vulnDiff, cleanDiff, rules, func() error {
		return fmt.Errorf("unit test TestAuth failed: assertion failed")
	})
	if resTestFail.Status != "regression_failure" {
		t.Fatalf("expected status 'regression_failure', got %q", resTestFail.Status)
	}

	// 5. Genuinely fixed and verified -> fixed
	resFixed := VerifyRemediation(finding, vulnDiff, cleanDiff, rules, func() error {
		return nil
	})
	if resFixed.Status != "fixed" {
		t.Fatalf("expected status 'fixed', got %q (%s)", resFixed.Status, resFixed.Explanation)
	}
}

func TestValidateJudgeVerdicts(t *testing.T) {
	findings := []Finding{
		{
			ID:       "finding-101",
			Rule:     "timing-unsafe-compare",
			File:     "auth.go",
			Line:     15,
			Category: "secrets",
		},
		{
			ID:       "finding-102",
			Rule:     "websocket-origin",
			File:     "ws.go",
			Line:     8,
			Category: "transport",
		},
	}

	// Valid confirmed verdict with evidence & rationale
	v1 := JudgeVerdict{
		FindingID: "finding-101",
		Rule:      "timing-unsafe-compare",
		File:      "auth.go",
		Line:      15,
		Category:  "secrets",
		Verdict:   VerdictConfirmed,
		Rationale: "Direct string equality comparison on secret authentication token",
		Evidence:  "auth.go:15: return token == expectedToken",
	}

	// Valid dismissed verdict with rationale
	v2 := JudgeVerdict{
		FindingID: "finding-102",
		Rule:      "websocket-origin",
		File:      "ws.go",
		Line:      8,
		Category:  "transport",
		Verdict:   VerdictDismissed,
		Rationale: "WebSocket server runs in internal test harness with no ambient cookies",
	}

	res := ValidateVerdicts([]JudgeVerdict{v1, v2}, findings)
	if !res.Valid || res.ValidatedCount != 2 || res.RejectedCount != 0 {
		t.Fatalf("expected 2 valid verdicts, got %+v", res)
	}

	// Orphaned/unknown finding ID rejected
	vUnknown := JudgeVerdict{
		FindingID: "nonexistent-id",
		Verdict:   VerdictConfirmed,
		Rationale: "looks bad",
		Evidence:  "evidence text",
	}
	resUnknown := ValidateVerdicts([]JudgeVerdict{vUnknown}, findings)
	if resUnknown.Valid || resUnknown.RejectedCount != 1 {
		t.Fatalf("expected unknown finding to be rejected, got %+v", resUnknown)
	}

	// Duplicate verdict rejected
	resDup := ValidateVerdicts([]JudgeVerdict{v1, v1}, findings)
	if resDup.Valid || resDup.RejectedCount != 1 {
		t.Fatalf("expected duplicate verdict to be rejected, got %+v", resDup)
	}

	// Confirmed verdict missing evidence rejected
	vNoEvidence := v1
	vNoEvidence.FindingID = "finding-102"
	vNoEvidence.Rule = "websocket-origin"
	vNoEvidence.File = "ws.go"
	vNoEvidence.Line = 8
	vNoEvidence.Category = "transport"
	vNoEvidence.Evidence = ""
	resNoEvidence := ValidateVerdicts([]JudgeVerdict{vNoEvidence}, findings)
	if resNoEvidence.Valid || resNoEvidence.RejectedCount != 1 {
		t.Fatalf("expected missing evidence to be rejected, got %+v", resNoEvidence)
	}

	// Mutated finding attributes rejected
	vMutated := v1
	vMutated.File = "other_file.go"
	resMutated := ValidateVerdicts([]JudgeVerdict{vMutated}, findings)
	if resMutated.Valid || resMutated.RejectedCount != 1 {
		t.Fatalf("expected mutated file to be rejected, got %+v", resMutated)
	}
}

func TestIsVendorOrDependencyPath(t *testing.T) {
	cases := []struct {
		path     string
		isVendor bool
	}{
		{"node_modules/express/index.js", true},
		{"frontend/node_modules/react/index.js", true},
		{"vendor/github.com/pkg/errors/errors.go", true},
		{"pkg/vendor/module/mod.go", true},
		{"dist/bundle.js", true},
		{"build/output.js", true},
		{".bundle/gems/rails.rb", true},
		{"src/components/Button.tsx", false},
		{"internal/review/attestation.go", false},
		{"package.json", false},
		{"go.mod", false},
	}

	for _, tc := range cases {
		got := IsVendorOrDependencyPath(tc.path)
		if got != tc.isVendor {
			t.Errorf("IsVendorOrDependencyPath(%q) = %t, want %t", tc.path, got, tc.isVendor)
		}
	}
}
