package review

import (
	"testing"
)

func TestComputeRiskScore_FactorsAndBreakdown(t *testing.T) {
	finding := Finding{
		Rule:         "sql-injection",
		Category:     "security",
		Severity:     "critical",
		Confidence:   "proven",
		Reachability: "reachable",
		File:         "internal/api/handler.go",
		Line:         42,
		Message:      "Unsanitized parameter in query",
	}

	score, breakdown := ComputeRiskScore(finding)
	if score < 8.0 || score > 10.0 {
		t.Errorf("expected high risk score for reachable critical SQLi, got %f", score)
	}
	if breakdown == nil {
		t.Fatal("expected non-nil risk breakdown")
	}
	if breakdown.BaseSeverity != 9.5 {
		t.Errorf("expected base severity 9.5, got %f", breakdown.BaseSeverity)
	}
	if breakdown.ConfidenceFactor != 1.0 {
		t.Errorf("expected confidence factor 1.0, got %f", breakdown.ConfidenceFactor)
	}
	if breakdown.ReachabilityFactor != 1.0 {
		t.Errorf("expected reachability factor 1.0, got %f", breakdown.ReachabilityFactor)
	}
	if breakdown.ExposureFactor != 1.0 {
		t.Errorf("expected exposure factor 1.0, got %f", breakdown.ExposureFactor)
	}
	if breakdown.Explanation == "" {
		t.Errorf("expected non-empty explanation")
	}
}

func TestComputeRiskScore_UnknownReachabilityNotTreatedAsUnreachable(t *testing.T) {
	unknownFinding := Finding{
		Severity:     "high",
		Reachability: "", // unknown
		File:         "pkg/worker/task.go",
	}
	unreachableFinding := Finding{
		Severity:     "high",
		Reachability: "unreachable",
		File:         "pkg/worker/task.go",
	}

	scoreUnknown, breakdownUnknown := ComputeRiskScore(unknownFinding)
	scoreUnreachable, breakdownUnreachable := ComputeRiskScore(unreachableFinding)

	if breakdownUnknown.ReachabilityFactor <= breakdownUnreachable.ReachabilityFactor {
		t.Fatalf(
			"unknown reachability factor (%f) must be strictly greater than unreachable factor (%f)",
			breakdownUnknown.ReachabilityFactor, breakdownUnreachable.ReachabilityFactor,
		)
	}
	if scoreUnknown <= scoreUnreachable {
		t.Fatalf("score for unknown reachability (%f) must exceed unreachable score (%f)", scoreUnknown, scoreUnreachable)
	}
}

func TestComputeRiskScore_TestFileExposureDiscount(t *testing.T) {
	prodFinding := Finding{
		Severity: "high",
		File:     "pkg/auth/login.go",
	}
	testFinding := Finding{
		Severity: "high",
		File:     "pkg/auth/login_test.go",
	}

	scoreProd, _ := ComputeRiskScore(prodFinding)
	scoreTest, _ := ComputeRiskScore(testFinding)

	if scoreProd <= scoreTest {
		t.Errorf("prod finding risk score (%f) should exceed test file score (%f)", scoreProd, scoreTest)
	}
}

func TestCorrelateFindings_PreservesAllFindingsAndEvidence(t *testing.T) {
	findings := []Finding{
		{
			ID:       "id1",
			Rule:     "hardcoded-secret",
			Category: "security",
			Severity: "high",
			File:     "internal/auth/login.go",
			Line:     15,
			Evidence: []FindingEvidence{{Rule: "hardcoded-secret", Message: "found key"}},
		},
		{
			ID:       "id2",
			Rule:     "timing-attack",
			Category: "security",
			Severity: "medium",
			File:     "internal/auth/login.go",
			Line:     30,
			Evidence: []FindingEvidence{{Rule: "timing-attack", Message: "raw compare"}},
		},
		{
			ID:       "id3",
			Rule:     "resource-leak",
			Category: "resource",
			Severity: "low",
			File:     "cmd/main.go",
			Line:     50,
		},
	}

	correlated := CorrelateFindings(findings)

	if len(correlated) != len(findings) {
		t.Fatalf("expected count %d, got %d (findings must not be discarded)", len(findings), len(correlated))
	}
	for i := range findings {
		if correlated[i].ID != findings[i].ID {
			t.Errorf("finding %d ID altered: %s vs %s", i, correlated[i].ID, findings[i].ID)
		}
		if len(correlated[i].Evidence) != len(findings[i].Evidence) {
			t.Errorf("finding %d evidence altered", i)
		}
		if correlated[i].CorrelationID == "" {
			t.Errorf("finding %d missing CorrelationID", i)
		}
	}
}

func TestPrioritizeFindings_DeterministicOrdering(t *testing.T) {
	lowProd := Finding{
		ID:       "f1",
		Severity: "low",
		File:     "pkg/service.go",
		Line:     10,
	}
	critProd := Finding{
		ID:       "f2",
		Severity: "critical",
		File:     "pkg/service.go",
		Line:     20,
	}
	critTest := Finding{
		ID:       "f3",
		Severity: "critical",
		File:     "pkg/service_test.go",
		Line:     5,
	}

	sorted := PrioritizeFindings([]Finding{lowProd, critTest, critProd})

	if sorted[0].ID != "f2" {
		t.Errorf("expected highest risk finding (critical prod f2) first, got %s", sorted[0].ID)
	}
	if sorted[len(sorted)-1].ID != "f1" {
		t.Errorf("expected lowest risk finding last, got %s", sorted[len(sorted)-1].ID)
	}
}
