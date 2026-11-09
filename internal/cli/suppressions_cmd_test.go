package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func setupCLISuppressionRepo(t *testing.T) string {
	t.Helper()
	repoDir := t.TempDir()
	if out, err := exec.Command("git", "init", repoDir).CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v, out: %s", err, string(out))
	}
	return repoDir
}

func TestCLI_Suppressions(t *testing.T) {
	repoDir := setupCLISuppressionRepo(t)

	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}
	defer func() { _ = os.Chdir(origWd) }()

	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}

	// 1. Record an addition
	outRec, err := captureOutput(func() error {
		return Run([]string{
			"suppressions", "record",
			"--action", "add",
			"--rule", "hardcoded-credential",
			"--file", "server/auth.go",
			"--line", "25",
			"--reason", "Test dummy password",
			"--actor", "alice",
		})
	})
	if err != nil {
		t.Fatalf("suppressions record failed: %v, out:\n%s", err, outRec)
	}
	if !strings.Contains(outRec, "Recorded suppression event") {
		t.Errorf("expected success message, got:\n%s", outRec)
	}

	// 2. Audit inspection
	outAudit, err := captureOutput(func() error {
		return Run([]string{"suppressions", "audit"})
	})
	if err != nil {
		t.Fatalf("suppressions audit failed: %v, out:\n%s", err, outAudit)
	}
	if !strings.Contains(outAudit, "hardcoded-credential") || !strings.Contains(outAudit, "alice") {
		t.Errorf("expected audit output to show rule and actor, got:\n%s", outAudit)
	}

	// 3. Audit with --format json
	outJSON, err := captureOutput(func() error {
		return Run([]string{"suppressions", "audit", "--format", "json"})
	})
	if err != nil {
		t.Fatalf("suppressions audit --format json failed: %v", err)
	}
	if !strings.Contains(outJSON, `"total_events": 1`) || !strings.Contains(outJSON, `"alice"`) {
		t.Errorf("expected valid JSON audit response, got:\n%s", outJSON)
	}

	// 4. Verify flag (untampered)
	outVerify, err := captureOutput(func() error {
		return Run([]string{"suppressions", "audit", "--verify"})
	})
	if err != nil {
		t.Fatalf("suppressions audit --verify failed: %v", err)
	}
	if !strings.Contains(outVerify, "VERIFIED") {
		t.Errorf("expected output to contain VERIFIED, got:\n%s", outVerify)
	}

	// 5. Tamper with audit log and verify detection
	auditPath := filepath.Join(repoDir, ".m3tal-review", "suppressions", "audit.jsonl")
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log failed: %v", err)
	}
	tampered := strings.Replace(string(data), "Test dummy password", "Tampered reason", 1)
	if err := os.WriteFile(auditPath, []byte(tampered), 0644); err != nil {
		t.Fatalf("write tampered audit log failed: %v", err)
	}

	outTamper, err := captureOutput(func() error {
		return Run([]string{"suppressions", "audit", "--verify"})
	})
	if err == nil {
		t.Errorf("expected audit --verify to fail on tampered log!")
	}
	if !strings.Contains(outTamper, "TAMPER DETECTED") {
		t.Errorf("expected output to report TAMPER DETECTED, got:\n%s", outTamper)
	}
}
