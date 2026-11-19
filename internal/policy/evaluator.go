package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// EvaluationInput holds all analysis artifacts evaluated by the quality gate.
type EvaluationInput struct {
	Findings           []review.Finding
	ExecutedAnalyzers  []string
	FailedAnalyzers    []string
	IncompleteAnalysis bool
	Suppressions       []SuppressionRecord
	DryRun             bool
	Now                time.Time
}

func checkRequiredAnalyzers(
	policy QualityGatePolicy,
	input EvaluationInput,
) []GateViolation {
	var violations []GateViolation
	execSet := make(map[string]bool)
	for _, a := range input.ExecutedAnalyzers {
		execSet[a] = true
	}
	failedSet := make(map[string]bool)
	for _, a := range input.FailedAnalyzers {
		failedSet[a] = true
	}

	for _, req := range policy.RequiredAnalyzers {
		if failedSet[req] {
			msg := fmt.Sprintf("Required analyzer %q execution failed", req)
			violations = append(violations, NewGateViolation("analyzer", "", req, msg, ""))
		} else if !execSet[req] {
			msg := fmt.Sprintf("Required analyzer %q was not executed", req)
			violations = append(violations, NewGateViolation("analyzer", "", req, msg, ""))
		}
	}
	return violations
}

func buildValidSuppressionMap(
	policy QualityGatePolicy,
	input EvaluationInput,
) (map[string]bool, []GateViolation) {
	validMap := make(map[string]bool)
	var violations []GateViolation

	for _, s := range input.Suppressions {
		ok, reason := ValidateSuppression(policy.Suppression, s, input.Now)
		if ok {
			validMap[s.FindingID] = true
		} else {
			violations = append(violations, NewGateViolation("suppression", s.FindingID, s.Rule, reason, ""))
		}
	}
	return validMap, violations
}

func evaluateSingleFinding(
	policy QualityGatePolicy,
	f review.Finding,
	now time.Time,
) (GateViolation, bool) {
	ruleID := f.Rule
	if ruleID == "" && len(f.Rules) > 0 {
		ruleID = f.Rules[0]
	}

	maxSev, disabled, precedence := ResolveEffectiveRule(policy, f.File, ruleID)
	if disabled {
		return GateViolation{}, false
	}

	if policy.MinConfidence != "" && !ConfidenceMeets(f.Confidence, policy.MinConfidence) {
		return GateViolation{}, false
	}

	if maxSev != "" && SeverityExceeds(f.Severity, maxSev) {
		msg := fmt.Sprintf("Finding severity %q exceeds policy threshold %q", f.Severity, maxSev)
		return NewGateViolation("severity", f.ID, ruleID, msg, precedence), true
	}

	if policy.MaxRiskScore > 0 && f.RiskScore > policy.MaxRiskScore {
		msg := fmt.Sprintf("Finding risk score %.1f exceeds maximum threshold %.1f", f.RiskScore, policy.MaxRiskScore)
		return NewGateViolation("risk", f.ID, ruleID, msg, precedence), true
	}

	return GateViolation{}, false
}

// EvaluateQualityGate evaluates review outputs against a deterministic QualityGatePolicy.
func EvaluateQualityGate(
	ctx context.Context,
	policy QualityGatePolicy,
	input EvaluationInput,
) GateEvaluation {
	now := input.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var violations []GateViolation
	var warnings []GateViolation
	var explanations []string

	// 1. Incomplete analysis checks
	if policy.FailOnIncomplete && input.IncompleteAnalysis {
		violations = append(violations, GateViolation{
			Category:   "incomplete",
			Message:    "Analysis is incomplete or truncated due to resource budgets",
			Precedence: "repository_default",
		})
	}

	// 2. Required analyzers checks
	violations = append(violations, checkRequiredAnalyzers(policy, input)...)

	// 3. Suppression checks
	validSuppressions, suppViolations := buildValidSuppressionMap(policy, input)
	violations = append(violations, suppViolations...)

	// 4. Finding evaluations
	for _, f := range input.Findings {
		if validSuppressions[f.ID] {
			continue
		}
		if v, ok := evaluateSingleFinding(policy, f, now); ok {
			violations = append(violations, v)
		}
	}

	// 5. Compute status & exit code
	var status GateStatus
	var exitCode int
	switch {
	case len(violations) > 0 && policy.FailOnIncomplete && input.IncompleteAnalysis:
		status = GateIncomplete
		exitCode = 2
		explanations = append(explanations, "Quality gate incomplete: analysis incomplete under fail_on_incomplete")
	case len(violations) > 0:
		status = GateFailed
		exitCode = 1
		explanations = append(explanations, fmt.Sprintf("Quality gate failed: %d violation(s)", len(violations)))
	case len(warnings) > 0:
		status = GateWarning
		exitCode = 0
		explanations = append(explanations, "Quality gate passed with warnings")
	default:
		status = GatePassed
		exitCode = 0
		explanations = append(explanations, "Quality gate passed: all criteria met")
	}

	return GateEvaluation{
		Status:      status,
		ExitCode:    exitCode,
		Violations:  violations,
		Warnings:    warnings,
		Explanation: explanations,
		DryRun:      input.DryRun,
		EvaluatedAt: now,
	}
}
