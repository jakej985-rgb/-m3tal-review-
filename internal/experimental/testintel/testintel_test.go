package testintel

import (
	"context"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

const sampleTestSource = `package mypkg

import "testing"

func TestDirectHandler(t *testing.T) {}

func TestDirectHandler_Regression(t *testing.T) {}

func TestIntegration_OutboundCall(t *testing.T) {}

func BenchmarkDirectHandler(b *testing.B) {}

func FuzzDirectHandler(f *testing.F) {}

func HelperNotATest() {}
`

func TestDiscoverTestsFromSource(t *testing.T) {
	targets, err := DiscoverTestsFromSource("mypkg/handler_test.go", sampleTestSource)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 5 {
		t.Fatalf("expected 5 test targets, got %d", len(targets))
	}

	kinds := make(map[TestKind]int)
	for _, target := range targets {
		kinds[target.Kind]++
	}

	if kinds[TestKindUnit] != 1 {
		t.Errorf("expected 1 unit test, got %d", kinds[TestKindUnit])
	}
	if kinds[TestKindRegression] != 1 {
		t.Errorf("expected 1 regression test, got %d", kinds[TestKindRegression])
	}
	if kinds[TestKindIntegration] != 1 {
		t.Errorf("expected 1 integration test, got %d", kinds[TestKindIntegration])
	}
	if kinds[TestKindBenchmark] != 1 {
		t.Errorf("expected 1 benchmark, got %d", kinds[TestKindBenchmark])
	}
	if kinds[TestKindFuzz] != 1 {
		t.Errorf("expected 1 fuzz test, got %d", kinds[TestKindFuzz])
	}
}

func TestMapFindingToTests(t *testing.T) {
	tests := []TestTarget{
		{
			Package: "mypkg",
			File:    "mypkg/handler_test.go",
			Name:    "TestDirectHandler",
			Kind:    TestKindUnit,
		},
		{
			Package: "mypkg",
			File:    "mypkg/other_test.go",
			Name:    "TestOtherThing",
			Kind:    TestKindUnit,
		},
		{
			Package: "unrelated",
			File:    "unrelated/unrelated_test.go",
			Name:    "TestUnrelated",
			Kind:    TestKindUnit,
		},
	}

	finding := review.Finding{
		ID:       "f-1",
		Rule:     "flow-path-traversal",
		File:     "mypkg/handler.go",
		Line:     18,
		Message:  "Untrusted data flows into os.Open in DirectHandler",
		Severity: "high",
		Metadata: map[string]string{"function": "DirectHandler"},
	}

	assocs := MapFindingToTests(finding, tests)
	if len(assocs) == 0 {
		t.Fatalf("expected associations for finding")
	}

	// Test 1: DirectHandler should be high confidence direct match
	if assocs[0].Test.Name != "TestDirectHandler" || assocs[0].Confidence != "high" {
		t.Errorf("expected first association to be high confidence TestDirectHandler, got %s (%s)",
			assocs[0].Test.Name, assocs[0].Confidence)
	}

	// False association rejection: unrelated package should NOT be in assocs
	for _, a := range assocs {
		if a.Test.Package == "unrelated" {
			t.Errorf("unexpected association with unrelated package test")
		}
	}
}

func TestCoverageAssessment(t *testing.T) {
	finding := review.Finding{
		ID:       "f-sec",
		Rule:     "flow-command-injection",
		File:     "exec/run.go",
		Severity: "critical",
		Message:  "command injection in RunCmd",
	}

	// 1. Zero coverage
	covNone := AssessTestCoverage(finding, nil)
	if covNone.Level != CoverageNone {
		t.Errorf("expected CoverageNone, got %s", covNone.Level)
	}
	if !strings.Contains(covNone.GapRisk, "CRITICAL_GAP") {
		t.Errorf("expected CRITICAL_GAP risk for uncovered critical finding")
	}

	// 2. Weak coverage
	weakAssoc := []TestAssociation{
		{
			FindingID:  finding.ID,
			Test:       TestTarget{Name: "TestGeneralPackage"},
			Kind:       AssocPackageColocate,
			Confidence: "low",
		},
	}
	covWeak := AssessTestCoverage(finding, weakAssoc)
	if covWeak.Level != CoverageWeak {
		t.Errorf("expected CoverageWeak, got %s", covWeak.Level)
	}
	if !strings.Contains(covWeak.GapRisk, "HIGH_GAP") {
		t.Errorf("expected HIGH_GAP risk for weakly covered critical finding")
	}

	// 3. Covered
	strongAssoc := []TestAssociation{
		{
			FindingID:  finding.ID,
			Test:       TestTarget{Name: "TestRunCmd_Regression", Kind: TestKindRegression},
			Kind:       AssocDirectSymbol,
			Confidence: "high",
		},
	}
	covCovered := AssessTestCoverage(finding, strongAssoc)
	if covCovered.Level != CoverageCovered {
		t.Errorf("expected CoverageCovered, got %s", covCovered.Level)
	}
	if covCovered.GapRisk != "" {
		t.Errorf("expected empty gap risk when properly covered, got %s", covCovered.GapRisk)
	}
}

func TestSuggestRegressionTest(t *testing.T) {
	finding := review.Finding{
		ID:       "f-sqli",
		Rule:     "flow-sql-injection",
		File:     "db/query.go",
		Message:  "SQL injection in QueryUser",
		Metadata: map[string]string{"function": "QueryUser"},
	}

	suggestion := SuggestRegressionTest(finding)
	if suggestion.TargetFile != "db/query_test.go" {
		t.Errorf("target file want db/query_test.go, got %s", suggestion.TargetFile)
	}
	if !strings.Contains(suggestion.FunctionName, "TestQueryUser_Regression_FlowSqlInjection") {
		t.Errorf("function name want regression format, got %s", suggestion.FunctionName)
	}
	if !strings.Contains(suggestion.Disclaimer, "PROPOSAL ONLY") {
		t.Errorf("missing proposal disclaimer in suggestion")
	}
	if !strings.Contains(suggestion.ProposedCode, "func TestQueryUser_Regression") {
		t.Errorf("proposed code missing test skeleton")
	}
}

type mockRunner struct {
	passed bool
	output string
}

func (m *mockRunner) RunTest(ctx context.Context, pkg, test string) (bool, string, error) {
	return m.passed, m.output, nil
}

type mockAnalyzer struct {
	findings []review.Finding
}

func (m *mockAnalyzer) ReAnalyze(ctx context.Context) ([]review.Finding, error) {
	return m.findings, nil
}

func execMockVerification(baseline review.Finding, prior, post []review.Finding) VerificationResult {
	return VerifyRemediation(
		context.Background(),
		&mockRunner{passed: true, output: "PASS"},
		&mockAnalyzer{findings: post},
		VerifyOptions{
			TargetTest:      "TestFetch_Regression",
			BaselineFinding: baseline,
			PriorFindings:   prior,
		},
	)
}

func TestVerifyRemediation(t *testing.T) {
	baseline := review.Finding{
		ID:   "f-base",
		Rule: "flow-ssrf",
		File: "net/fetch.go",
		Line: 42,
	}

	prior := []review.Finding{baseline}

	// Case 1: Ideal fix - test passes, finding resolved, no collateral
	resSuccess := execMockVerification(baseline, prior, nil)
	if resSuccess.Status != ProofVerifiedAbsence {
		t.Errorf("want ProofVerifiedAbsence, got %s", resSuccess.Status)
	}
	if !resSuccess.FindingResolved || !resSuccess.TestsPassed {
		t.Errorf("expected finding resolved and tests passed")
	}
	if !strings.Contains(resSuccess.EpistemicLimits, "Passing tests demonstrate absence") {
		t.Errorf("missing epistemic limits disclaimer")
	}

	// Case 2: Incomplete fix - test passes, but finding still detected
	resIncomplete := execMockVerification(baseline, prior, []review.Finding{baseline})
	if resIncomplete.Status != ProofPartiallyVerified {
		t.Errorf("want ProofPartiallyVerified, got %s", resIncomplete.Status)
	}
	if resIncomplete.FindingResolved {
		t.Errorf("expected finding not resolved")
	}

	// Case 3: Fix with collateral finding introduced
	collateralFinding := review.Finding{
		ID:   "f-collat",
		Rule: "resource-leak",
		File: "net/fetch.go",
		Line: 50,
	}
	resCollateral := execMockVerification(baseline, prior, []review.Finding{collateralFinding})
	if len(resCollateral.CollateralFindings) != 1 {
		t.Fatalf("expected 1 collateral finding, got %d", len(resCollateral.CollateralFindings))
	}
	if resCollateral.Status != ProofPartiallyVerified {
		t.Errorf("want ProofPartiallyVerified on collateral, got %s", resCollateral.Status)
	}
}
