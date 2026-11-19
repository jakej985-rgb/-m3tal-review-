package testintel

import (
	"fmt"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// AssessTestCoverage analyzes test associations for a finding and identifies coverage gaps.
func AssessTestCoverage(f review.Finding, assocs []TestAssociation) CoverageAssessment {
	ruleID := FindingRuleID(f)

	var hasHigh, hasDirect, hasRegression bool
	for _, a := range assocs {
		if a.Confidence == "high" {
			hasHigh = true
		}
		if a.Kind == AssocDirectSymbol {
			hasDirect = true
		}
		if a.Test.Kind == TestKindRegression {
			hasRegression = true
		}
	}

	var level CoverageLevel
	var summary string
	switch {
	case len(assocs) == 0:
		level = CoverageNone
		summary = fmt.Sprintf("No test targets discovered for finding in %s", f.File)
	case !hasHigh && !hasDirect:
		level = CoverageWeak
		summary = fmt.Sprintf("Only weak or indirect package tests found (%d tests)", len(assocs))
	default:
		level = CoverageCovered
		summary = fmt.Sprintf("Targeted tests identified (%d tests, direct=%t, regression=%t)",
			len(assocs), hasDirect, hasRegression)
	}

	gapRisk := computeGapRisk(f.Severity, level, hasRegression)

	return CoverageAssessment{
		FindingID:    f.ID,
		RuleID:       ruleID,
		Severity:     f.Severity,
		Level:        level,
		Summary:      summary,
		Associations: assocs,
		GapRisk:      gapRisk,
	}
}

func computeGapRisk(severity string, level CoverageLevel, hasRegression bool) string {
	sev := strings.ToLower(severity)
	isCriticalOrHigh := sev == "critical" || sev == "high"

	switch {
	case isCriticalOrHigh && level == CoverageNone:
		return "CRITICAL_GAP: Unverified security defect with zero test coverage"
	case isCriticalOrHigh && level == CoverageWeak:
		return "HIGH_GAP: Security defect lacks dedicated unit or regression tests"
	case isCriticalOrHigh && !hasRegression:
		return "MEDIUM_GAP: General unit tests exist, but dedicated regression test is missing"
	case level == CoverageNone:
		return "LOW_GAP: No tests discovered for modified path"
	default:
		return ""
	}
}
