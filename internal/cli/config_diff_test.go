package cli

import (
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_ConfigDiff(t *testing.T) {
	repoDir := t.TempDir()
	if out, err := exec.Command("git", "init", repoDir).CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v, out: %s", err, string(out))
	}

	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}
	defer func() { _ = os.Chdir(origWd) }()

	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}

	// 1. Create base policy
	basePolicyPath := filepath.Join(repoDir, ".m3tal-review-policy.json")
	basePolicyContent := []byte(`{
		"risk_paths": ["old_crypto/**"],
		"rules": {
			"code-slop": {"severity": "medium"}
		}
	}`)
	if err := os.WriteFile(basePolicyPath, basePolicyContent, 0644); err != nil {
		t.Fatalf("write base policy failed: %v", err)
	}

	// 2. Create proposed policy
	proposedPolicyPath := filepath.Join(repoDir, "proposed-policy.json")
	proposedPolicyContent := []byte(`{
		"risk_paths": ["old_crypto/**", "new_auth/**"],
		"rules": {
			"code-slop": {"severity": "info"}
		}
	}`)
	if err := os.WriteFile(proposedPolicyPath, proposedPolicyContent, 0644); err != nil {
		t.Fatalf("write proposed policy failed: %v", err)
	}

	hashBefore := sha256.Sum256(proposedPolicyContent)

	// 3. Test config diff
	outText, err := captureOutput(func() error {
		return Run([]string{"config", "diff", proposedPolicyPath})
	})
	if err != nil {
		t.Fatalf("config diff failed: %v, out:\n%s", err, outText)
	}
	if !strings.Contains(outText, "new_auth/**") || !strings.Contains(outText, "code-slop") {
		t.Errorf("expected diff to show new_auth and code-slop changes, got:\n%s", outText)
	}

	// 4. Test policy diff
	outPolicyDiff, err := captureOutput(func() error {
		return Run([]string{"policy", "diff", proposedPolicyPath})
	})
	if err != nil {
		t.Fatalf("policy diff failed: %v", err)
	}
	if !strings.Contains(outPolicyDiff, "new_auth/**") {
		t.Errorf("expected policy diff output, got:\n%s", outPolicyDiff)
	}

	// 5. Test policy dry-run
	outDryRun, err := captureOutput(func() error {
		return Run([]string{"policy", "dry-run", proposedPolicyPath})
	})
	if err != nil {
		t.Fatalf("policy dry-run failed: %v", err)
	}
	if !strings.Contains(outDryRun, "new_auth/**") {
		t.Errorf("expected policy dry-run output, got:\n%s", outDryRun)
	}

	// 6. Test JSON format
	outJSON, err := captureOutput(func() error {
		return Run([]string{"config", "diff", proposedPolicyPath, "--format", "json"})
	})
	if err != nil {
		t.Fatalf("config diff --format json failed: %v", err)
	}
	if !strings.Contains(outJSON, `"has_changes": true`) || !strings.Contains(outJSON, `"new_auth/**"`) {
		t.Errorf("expected valid JSON diff, got:\n%s", outJSON)
	}

	// 7. Verify non-mutation
	currentProposed, err := os.ReadFile(proposedPolicyPath)
	if err != nil {
		t.Fatalf("read proposed failed: %v", err)
	}
	if sha256.Sum256(currentProposed) != hashBefore {
		t.Errorf("proposed policy file was mutated during diff/dry-run!")
	}

	// 8. Test invalid proposed policy validation
	badPolicyPath := filepath.Join(repoDir, "bad-policy.json")
	if err := os.WriteFile(badPolicyPath, []byte(`{"risk_paths": [""]}`), 0644); err != nil {
		t.Fatalf("write bad policy failed: %v", err)
	}

	outBad, err := captureOutput(func() error {
		return Run([]string{"config", "diff", badPolicyPath})
	})
	if err == nil {
		t.Errorf("expected config diff on invalid policy to fail")
	}
	if !strings.Contains(outBad, "FAILED") {
		t.Errorf("expected validation failure output, got:\n%s", outBad)
	}
}
