package policy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestEvaluateQualityGate_Thresholds(t *testing.T) {
	policy := QualityGatePolicy{
		Version:       "1.0",
		MaxSeverity:   "high",
		MinConfidence: "medium",
	}

	criticalFinding := review.Finding{
		ID:         "f-crit",
		Rule:       "flow-sqli",
		Severity:   "critical",
		Confidence: "high",
		File:       "app/db.go",
	}

	input := EvaluationInput{
		Findings: []review.Finding{criticalFinding},
	}

	eval := EvaluateQualityGate(context.Background(), policy, input)
	if eval.Status != GateFailed {
		t.Errorf("expected GateFailed, got %s", eval.Status)
	}
	if eval.ExitCode != 1 {
		t.Errorf("expected ExitCode 1, got %d", eval.ExitCode)
	}
	if len(eval.Violations) == 0 {
		t.Fatalf("expected violations")
	}
	if eval.Violations[0].Category != "severity" {
		t.Errorf("expected severity violation, got %s", eval.Violations[0].Category)
	}
}

func TestEvaluateQualityGate_RequiredAnalyzers(t *testing.T) {
	policy := QualityGatePolicy{
		Version:           "1.0",
		RequiredAnalyzers: []string{"flow", "concurrency"},
	}

	// Case 1: Required analyzer missing
	inputMissing := EvaluationInput{
		ExecutedAnalyzers: []string{"concurrency"},
	}
	evalMissing := EvaluateQualityGate(context.Background(), policy, inputMissing)
	if evalMissing.Status != GateFailed {
		t.Errorf("expected GateFailed when required analyzer missing, got %s", evalMissing.Status)
	}

	// Case 2: Required analyzer failed
	inputFailed := EvaluationInput{
		ExecutedAnalyzers: []string{"flow", "concurrency"},
		FailedAnalyzers:   []string{"flow"},
	}
	evalFailed := EvaluateQualityGate(context.Background(), policy, inputFailed)
	if evalFailed.Status != GateFailed {
		t.Errorf("expected GateFailed when required analyzer failed, got %s", evalFailed.Status)
	}
}

func TestEvaluateQualityGate_IncompleteAnalysis(t *testing.T) {
	policy := QualityGatePolicy{
		Version:          "1.0",
		FailOnIncomplete: true,
	}

	input := EvaluationInput{
		IncompleteAnalysis: true,
	}

	eval := EvaluateQualityGate(context.Background(), policy, input)
	if eval.Status != GateIncomplete {
		t.Errorf("expected GateIncomplete, got %s", eval.Status)
	}
	if eval.ExitCode != 2 {
		t.Errorf("expected exit code 2 on incomplete, got %d", eval.ExitCode)
	}
}

func TestEvaluateQualityGate_PathOverrides(t *testing.T) {
	policy := QualityGatePolicy{
		Version:     "1.0",
		MaxSeverity: "high",
		PathOverrides: []PathOverride{
			{
				Pattern:     "test/*",
				MaxSeverity: "critical", // tests allow high findings
			},
			{
				Pattern:       "legacy/*",
				DisabledRules: []string{"flow-sqli"},
			},
		},
	}

	// Finding in test/ path is allowed because max severity is critical
	testFinding := review.Finding{
		ID:         "f-test",
		Rule:       "flow-path-traversal",
		Severity:   "high",
		Confidence: "high",
		File:       "test/suite.go",
	}

	// Finding in legacy/ path is ignored because rule is disabled
	legacyFinding := review.Finding{
		ID:         "f-legacy",
		Rule:       "flow-sqli",
		Severity:   "critical",
		Confidence: "high",
		File:       "legacy/old.go",
	}

	input := EvaluationInput{
		Findings: []review.Finding{testFinding, legacyFinding},
	}

	eval := EvaluateQualityGate(context.Background(), policy, input)
	if eval.Status != GatePassed {
		t.Errorf("expected GatePassed under path overrides, got %s", eval.Status)
	}
}

func TestEvaluateQualityGate_Suppressions(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	future := now.Add(48 * time.Hour)
	past := now.Add(-48 * time.Hour)

	policy := QualityGatePolicy{
		Version:     "1.0",
		MaxSeverity: "medium",
		Suppression: SuppressionRule{
			RequireReason: true,
			RequireExpiry: true,
		},
	}

	finding := review.Finding{
		ID:       "f-supp",
		Rule:     "sec-leak",
		Severity: "high",
		File:     "core/main.go",
	}

	// 1. Valid suppression
	validSupp := SuppressionRecord{
		FindingID: "f-supp",
		Rule:      "sec-leak",
		Reason:    "Accepted temporary risk for staging test",
		ExpiresAt: &future,
	}
	evalValid := EvaluateQualityGate(context.Background(), policy, EvaluationInput{
		Findings:     []review.Finding{finding},
		Suppressions: []SuppressionRecord{validSupp},
		Now:          now,
	})
	if evalValid.Status != GatePassed {
		t.Errorf("expected GatePassed with valid suppression, got %s", evalValid.Status)
	}

	// 2. Expired suppression
	expiredSupp := SuppressionRecord{
		FindingID: "f-supp",
		Rule:      "sec-leak",
		Reason:    "Accepted temporary risk for staging test",
		ExpiresAt: &past,
	}
	evalExpired := EvaluateQualityGate(context.Background(), policy, EvaluationInput{
		Findings:     []review.Finding{finding},
		Suppressions: []SuppressionRecord{expiredSupp},
		Now:          now,
	})
	if evalExpired.Status != GateFailed {
		t.Errorf("expected GateFailed with expired suppression, got %s", evalExpired.Status)
	}
}

func TestValidatePolicySchema(t *testing.T) {
	// 1. Missing version
	errNoVer := ValidatePolicySchema(QualityGatePolicy{})
	if errNoVer == nil || !strings.Contains(errNoVer.Error(), "version") {
		t.Errorf("expected version error, got %v", errNoVer)
	}

	// 2. Invalid severity
	errBadSev := ValidatePolicySchema(QualityGatePolicy{
		Version:     "1.0",
		MaxSeverity: "ultra-high",
	})
	if errBadSev == nil || !strings.Contains(errBadSev.Error(), "max_severity") {
		t.Errorf("expected severity error, got %v", errBadSev)
	}

	// 3. Valid policy
	errValid := ValidatePolicySchema(QualityGatePolicy{
		Version:       "1.0",
		MaxSeverity:   "high",
		MinConfidence: "medium",
	})
	if errValid != nil {
		t.Errorf("unexpected error on valid policy: %v", errValid)
	}
}
