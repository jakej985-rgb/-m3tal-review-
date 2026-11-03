package review

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyRulesProduceRiskAndDriftFindings(t *testing.T) {
	root := t.TempDir()
	policy := `{
  "risk_paths": ["internal/auth/**"],
  "forbidden_paths": ["internal/legacy/**"],
  "require_together": [
    {"when_changed": "api/openapi.yaml", "also_change": ["docs/api/**"]}
  ]
}`
	if err := os.WriteFile(filepath.Join(root, policyFileName), []byte(policy), 0644); err != nil {
		t.Fatal(err)
	}
	diff := "diff --git a/internal/auth/login.go b/internal/auth/login.go\n" +
		"diff --git a/internal/legacy/old.go b/internal/legacy/old.go\n" +
		"diff --git a/api/openapi.yaml b/api/openapi.yaml\n"

	risk := (RiskRule{RepositoryRoot: root, WorkingTree: true}).Check(diff)
	if len(risk) != 1 || risk[0].Category != "risk" || risk[0].Severity != "info" {
		t.Fatalf("risk findings = %+v", risk)
	}
	drift := (PolicyRule{RepositoryRoot: root, WorkingTree: true}).Check(diff)
	if len(drift) != 2 {
		t.Fatalf("drift findings = %+v, want forbidden path and missing coupled change", drift)
	}
	for _, finding := range drift {
		if finding.Category != "drift" || finding.Rule != "review-policy" {
			t.Errorf("unexpected finding category/rule: %+v", finding)
		}
	}
}

func TestPolicyRuleRejectsMalformedConfiguration(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, policyFileName), []byte(`{"forbidden_paths":["["]}`), 0644); err != nil {
		t.Fatal(err)
	}
	findings := (PolicyRule{RepositoryRoot: root, WorkingTree: true}).Check("diff --git a/main.go b/main.go\n")
	if len(findings) != 1 || findings[0].Rule != "review-policy-config-error" || findings[0].Category != "confidence" {
		t.Fatalf("configuration findings = %+v", findings)
	}
}
