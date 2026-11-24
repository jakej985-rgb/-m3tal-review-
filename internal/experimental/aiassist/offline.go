// Package aiassist provides offline deterministic fallback assistance.
package aiassist

import (
	"context"
	"fmt"
	"strings"
)

// OfflineProvider produces deterministic guidance without external network calls.
type OfflineProvider struct{}

// Name returns the provider identifier.
func (p *OfflineProvider) Name() string {
	return "offline-deterministic"
}

func handleExplain(findings []FindingSummary) []FindingAdvice {
	var list []FindingAdvice
	for _, f := range findings {
		summary := fmt.Sprintf("Heuristic rule %s flagged %s:%d", f.RuleID, f.File, f.Line)
		impact := fmt.Sprintf("Reported severity is %s; pattern detected in AST", f.Severity)
		list = append(list, FindingAdvice{
			FindingID:          f.ID,
			Summary:            summary,
			PotentialImpact:    impact,
			EvidenceReferences: []string{fmt.Sprintf("%s:%d", f.File, f.Line)},
		})
	}
	return list
}

func handleSummary(findings []FindingSummary) string {
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	return fmt.Sprintf(
		"Deterministic analysis surfaced %d findings (%d crit, %d high, %d med, %d low).",
		len(findings), counts["critical"], counts["high"], counts["medium"], counts["low"],
	)
}

func addHypothesis(list *[]CoverageHypothesis, pattern, rule, rationale, vuln string) {
	*list = append(*list, CoverageHypothesis{
		Pattern:                pattern,
		ProposedRule:           rule,
		Rationale:              rationale,
		SuspectedVulnerability: vuln,
	})
}

func handleHypotheses(diff string) []CoverageHypothesis {
	var list []CoverageHypothesis
	if strings.Contains(diff, "http.") || strings.Contains(diff, "net/http") {
		addHypothesis(&list, "HTTP handler modification", "check-http-timeouts",
			"New HTTP handlers should declare explicit server timeouts",
			"Denial of service through slowloris connection starvation")
	}
	if strings.Contains(diff, "sql") || strings.Contains(diff, "Query") {
		addHypothesis(&list, "Database query execution", "check-sql-parameterization",
			"Dynamic queries must use parameterized placeholders", "SQL Injection")
	}
	hypotheses := list
	return hypotheses
}

func handleTriage(findings []FindingSummary) []TriageAdvice {
	var list []TriageAdvice
	for _, f := range findings {
		prio := "P2"
		if f.Severity == "critical" {
			prio = "P0"
		} else if f.Severity == "high" {
			prio = "P1"
		}
		reason := fmt.Sprintf("Based on severity %s and impacted file %s", f.Severity, f.File)
		list = append(list, TriageAdvice{
			FindingID:          f.ID,
			SuggestedPriority:  prio,
			HeuristicReasoning: reason,
		})
	}
	triage := list
	return triage
}

func handleRemediation(findings []FindingSummary) *RemediationProposal {
	if len(findings) == 0 {
		return nil
	}
	target := findings[0]
	desc := fmt.Sprintf("Remediation suggestion for %s in %s", target.RuleID, target.File)
	patch := fmt.Sprintf("--- %s\n+++ %s\n// Fix for %s", target.File, target.File, target.RuleID)
	testP := fmt.Sprintf("// Regression test for %s\nfunc TestRegression_%s(t *testing.T) {}",
		target.RuleID, target.RuleID)
	return &RemediationProposal{
		FindingID:        target.ID,
		Description:      desc,
		DiffPatch:        patch,
		TestPatch:        testP,
		RequiresApproval: true,
		IsAuthoritative:  false,
	}
}

// GenerateAdvice implements the Provider interface using local heuristics.
func (p *OfflineProvider) GenerateAdvice(
	_ context.Context,
	req AssistanceRequest,
) (*AssistanceResponse, error) {
	resp := &AssistanceResponse{
		Task:         req.Task,
		ProviderName: p.Name(),
	}

	switch req.Task {
	case TaskExplainFinding:
		resp.Explanations = handleExplain(req.Findings)
	case TaskSummarizeReview:
		resp.ReviewSummary = handleSummary(req.Findings)
	case TaskHypothesizeCoverage:
		resp.Hypotheses = handleHypotheses(req.DiffSnippet)
	case TaskSuggestTriage:
		resp.Triage = handleTriage(req.Findings)
	case TaskProposeRemediation:
		resp.Proposal = handleRemediation(req.Findings)
	}

	ApplyBoundaryGuards(resp)
	return resp, nil
}
