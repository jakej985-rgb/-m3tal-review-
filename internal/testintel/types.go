package testintel

import (
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// TestKind classifies the style of a discovered test target.
type TestKind string

const (
	TestKindUnit        TestKind = "unit"
	TestKindIntegration TestKind = "integration"
	TestKindBenchmark   TestKind = "benchmark"
	TestKindFuzz        TestKind = "fuzz"
	TestKindRegression  TestKind = "regression"
)

// TestTarget represents a concrete test target discovered in source files.
type TestTarget struct {
	Package  string   `json:"package"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Name     string   `json:"name"`
	Kind     TestKind `json:"kind"`
	Function string   `json:"function,omitempty"`
}

// AssociationKind classifies how a test was matched to a finding.
type AssociationKind string

const (
	AssocDirectSymbol    AssociationKind = "direct_symbol"
	AssocEvidenceTrace   AssociationKind = "evidence_trace"
	AssocPackageColocate AssociationKind = "package_colocated"
	AssocHeuristic       AssociationKind = "heuristic"
)

// TestAssociation connects a finding to a relevant test target with rationale.
type TestAssociation struct {
	FindingID  string          `json:"finding_id"`
	Test       TestTarget      `json:"test"`
	Kind       AssociationKind `json:"kind"`
	Confidence string          `json:"confidence"` // "high", "medium", "low"
	Rationale  string          `json:"rationale"`
}

// CoverageLevel classifies test coverage for a finding's vulnerable path.
type CoverageLevel string

const (
	CoverageNone    CoverageLevel = "none"
	CoverageWeak    CoverageLevel = "weak"
	CoverageCovered CoverageLevel = "covered"
)

// CoverageAssessment records the test coverage analysis for a finding.
type CoverageAssessment struct {
	FindingID    string            `json:"finding_id"`
	RuleID       string            `json:"rule_id"`
	Severity     string            `json:"severity"`
	Level        CoverageLevel     `json:"level"`
	Summary      string            `json:"summary"`
	Associations []TestAssociation `json:"associations,omitempty"`
	GapRisk      string            `json:"gap_risk,omitempty"`
}

// TestSuggestion is a non-binding proposed regression test case.
type TestSuggestion struct {
	FindingID    string    `json:"finding_id"`
	RuleID       string    `json:"rule_id"`
	TargetFile   string    `json:"target_file"`
	FunctionName string    `json:"function_name"`
	ProposedCode string    `json:"proposed_code"`
	Rationale    string    `json:"rationale"`
	Disclaimer   string    `json:"disclaimer"`
	CreatedAt    time.Time `json:"created_at"`
}

// ProofStatus describes the epistemic status of a verification outcome.
type ProofStatus string

const (
	ProofVerifiedAbsence   ProofStatus = "verified_absence_heuristic"
	ProofPartiallyVerified ProofStatus = "partially_verified"
	ProofUnverified        ProofStatus = "unverified"
)

// VerificationResult summarizes repair verification through tests and re-analysis.
type VerificationResult struct {
	FindingID          string           `json:"finding_id"`
	ProposalID         string           `json:"proposal_id,omitempty"`
	TestsPassed        bool             `json:"tests_passed"`
	TestOutput         string           `json:"test_output,omitempty"`
	FindingResolved    bool             `json:"finding_resolved"`
	CollateralFindings []review.Finding `json:"collateral_findings,omitempty"`
	Status             ProofStatus      `json:"status"`
	EpistemicLimits    string           `json:"epistemic_limits"`
	ExecutionTime      time.Duration    `json:"execution_time"`
}

// EpistemicDisclaimer is the standard warning regarding test results and correctness proofs.
const EpistemicDisclaimer = "Passing tests demonstrate absence of observed test failures, " +
	"not absence of defects or formal correctness. Static re-analysis confirms " +
	"the modeled rule pattern is no longer flagged under configured heuristics."

// FindingRuleID extracts the primary rule ID from a finding.
func FindingRuleID(f review.Finding) string {
	rule := f.Rule
	if rule == "" && len(f.Rules) > 0 {
		rule = f.Rules[0]
	}
	return rule
}
