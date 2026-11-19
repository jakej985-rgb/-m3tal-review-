package review

import (
	"strings"
	"testing"
)

func requireExplanation(t *testing.T, f Finding) *FindingExplanation {
	t.Helper()
	exp := ExplainFinding(f)
	if exp == nil {
		t.Fatalf("expected non-nil FindingExplanation for rule %s", f.Rule)
	}
	return exp
}

func TestExplainFindingBasic(t *testing.T) {
	f := Finding{
		ID:         "test-find-1",
		Rule:       "sql-injection",
		Severity:   "high",
		Confidence: "proven",
		File:       "internal/db/query.go",
		Line:       42,
		Message:    "Potential SQL injection via query formatting",
		RiskScore:  8.2,
		Risk: &RiskBreakdown{
			BaseSeverity:       8.0,
			ConfidenceFactor:   1.0,
			ReachabilityFactor: 1.0,
			ExposureFactor:     1.0,
			EvidenceMultiplier: 1.0,
			Explanation:        "base=8.0 * conf=1.00 -> 8.2",
		},
		Evidence: []FindingEvidence{
			{Message: "source request parameter 'q' in handler", Line: 20},
			{Message: "call QueryUsers(q) invoked", Line: 30},
			{Message: "sink db.Query(fmt.Sprintf(...)) executed", Line: 42},
			{Message: "inference: user input not validated by sanitizer", Line: 42},
		},
	}

	exp := requireExplanation(t, f)
	if !strings.Contains(exp.RuleRationale, "SQL query") {
		t.Errorf("unexpected RuleRationale: %s", exp.RuleRationale)
	}

	if exp.EvidenceKind != "source-to-sink" {
		t.Errorf("expected evidence kind 'source-to-sink', got '%s'", exp.EvidenceKind)
	}

	if len(exp.EvidenceSteps) != 4 {
		t.Fatalf("expected 4 evidence steps, got %d", len(exp.EvidenceSteps))
	}

	if exp.EvidenceSteps[0].Kind != "source" {
		t.Errorf("step 0 kind want 'source', got '%s'", exp.EvidenceSteps[0].Kind)
	}
	if exp.EvidenceSteps[2].Kind != "sink" {
		t.Errorf("step 2 kind want 'sink', got '%s'", exp.EvidenceSteps[2].Kind)
	}
	if !exp.EvidenceSteps[3].IsInference {
		t.Errorf("expected step 3 to be flagged as inference")
	}

	if len(exp.Inferences) != 1 {
		t.Errorf("expected 1 inference, got %d", len(exp.Inferences))
	}

	md := FormatExplanationMarkdown(exp)
	if !strings.Contains(md, "source-to-sink") || !strings.Contains(md, "(inference)") {
		t.Errorf("expected markdown to contain kind and inference mark: %s", md)
	}
}

func TestExplainFindingTruncatedAndLimitations(t *testing.T) {
	meta := map[string]string{
		"analysis_truncated":          "true",
		"analysis_truncation_reasons": "budget exceeded",
		"analysis_assumptions":        "unbuffered channels; serial execution",
	}
	res := ExplainFinding(Finding{
		Rule:         "deadlock",
		Severity:     "critical",
		Confidence:   "potential",
		File:         "worker.go",
		Reachability: "unknown",
		Metadata:     meta,
	})
	if res == nil || len(res.Assumptions) != 2 || len(res.Limitations) != 2 {
		t.Fatalf("unexpected assumptions/limitations: %+v", res)
	}
}

func TestRedactExcerpt(t *testing.T) {
	ghpPrefix := "gh" + "p_"
	awsPrefix := "AK" + "IA"
	raw := strings.Join([]string{
		"const token = \"" + ghpPrefix + "123456789012345678901234567890123456\"",
		"const auth = \"Bearer ya29.a0AfH6SM...\"",
		"const aws = \"" + awsPrefix + "1234567890ABCDEF\"",
		"password := \"super_secret_password\"",
		"fmt.Println(password)",
		"extra line 6",
		"extra line 7",
	}, "\n")

	redacted := RedactExcerpt(raw)

	if strings.Contains(redacted, "12345678901234567890") {
		t.Errorf("GitHub token was not redacted: %s", redacted)
	}
	if strings.Contains(redacted, "ya29.a0AfH6SM") {
		t.Errorf("Bearer token was not redacted: %s", redacted)
	}
	if strings.Contains(redacted, "ABCDEF") {
		t.Errorf("AWS key was not redacted: %s", redacted)
	}
	if strings.Contains(redacted, "super_secret_password") {
		t.Errorf("Password was not redacted: %s", redacted)
	}

	lines := strings.Split(strings.TrimSpace(redacted), "\n")
	if len(lines) > 6 { // 5 lines + ellipsis
		t.Errorf("excerpt line count exceeded bound: got %d lines", len(lines))
	}
}
