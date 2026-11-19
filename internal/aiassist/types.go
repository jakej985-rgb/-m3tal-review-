// Package aiassist provides deterministic-bounded AI assistance for code review.
package aiassist

import (
	"context"
	"time"
)

// TaskKind identifies the assistant workflow.
type TaskKind string

const (
	TaskExplainFinding      TaskKind = "explain_finding"
	TaskSummarizeReview     TaskKind = "summarize_review"
	TaskHypothesizeCoverage TaskKind = "hypothesize_coverage"
	TaskSuggestTriage       TaskKind = "suggest_triage"
	TaskProposeRemediation  TaskKind = "propose_remediation"
)

// Config configures the AI assistant execution boundaries.
type Config struct {
	Enabled         bool          `json:"enabled"`
	OptIn           bool          `json:"opt_in"`
	Timeout         time.Duration `json:"timeout"`
	MaxContextBytes int           `json:"max_context_bytes"`
	MaxTokens       int           `json:"max_tokens"`
}

// DefaultConfig returns safe default assistant parameters.
func DefaultConfig() Config {
	return Config{
		Enabled:         false,
		OptIn:           false,
		Timeout:         15 * time.Second,
		MaxContextBytes: 16 * 1024,
		MaxTokens:       1024,
	}
}

// FindingSummary describes a deterministic finding for AI assistance.
type FindingSummary struct {
	ID       string   `json:"id"`
	RuleID   string   `json:"rule_id"`
	Severity string   `json:"severity"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

// AssistanceRequest bundles input data and resource budgets for the assistant.
type AssistanceRequest struct {
	Task        TaskKind         `json:"task"`
	Findings    []FindingSummary `json:"findings"`
	DiffSnippet string           `json:"diff_snippet"`
	BudgetBytes int              `json:"budget_bytes"`
}

// RedactionRecord notes a detected and sanitized sensitive item.
type RedactionRecord struct {
	Kind   string `json:"kind"`
	Offset int    `json:"offset"`
}

// FindingAdvice provides explanation and contextual guidance for a finding.
type FindingAdvice struct {
	FindingID          string   `json:"finding_id"`
	Summary            string   `json:"summary"`
	PotentialImpact    string   `json:"potential_impact"`
	EvidenceReferences []string `json:"evidence_references,omitempty"`
}

// CoverageHypothesis suggests new rule ideas based on patterns in diffs.
type CoverageHypothesis struct {
	Pattern                string `json:"pattern"`
	ProposedRule           string `json:"proposed_rule"`
	Rationale              string `json:"rationale"`
	SuspectedVulnerability string `json:"suspected_vulnerability"`
}

// TriageAdvice provides non-authoritative priority suggestions.
type TriageAdvice struct {
	FindingID           string `json:"finding_id"`
	SuggestedPriority   string `json:"suggested_priority"`
	HeuristicReasoning  string `json:"heuristic_reasoning"`
	AuthoritativeNotice string `json:"authoritative_notice"`
}

// RemediationProposal encapsulates a suggested fix and regression test.
type RemediationProposal struct {
	FindingID        string `json:"finding_id"`
	Description      string `json:"description"`
	DiffPatch        string `json:"diff_patch"`
	TestPatch        string `json:"test_patch,omitempty"`
	RequiresApproval bool   `json:"requires_approval"`
	IsAuthoritative  bool   `json:"is_authoritative"`
}

// AssistanceResponse aggregates non-binding assistant outputs.
type AssistanceResponse struct {
	Task                TaskKind             `json:"task"`
	Disclaimers         []string             `json:"disclaimers"`
	Explanations        []FindingAdvice      `json:"explanations,omitempty"`
	ReviewSummary       string               `json:"review_summary,omitempty"`
	Hypotheses          []CoverageHypothesis `json:"hypotheses,omitempty"`
	Triage              []TriageAdvice       `json:"triage,omitempty"`
	Proposal            *RemediationProposal `json:"proposal,omitempty"`
	Redactions          []RedactionRecord    `json:"redactions,omitempty"`
	AuthoritativePolicy string               `json:"authoritative_policy"`
	ProviderName        string               `json:"provider_name"`
}

// Provider represents a model or engine generating assistance.
type Provider interface {
	Name() string
	GenerateAdvice(ctx context.Context, req AssistanceRequest) (*AssistanceResponse, error)
}
