// Package aiassist coordinates AI assistance workflows under deterministic boundaries.
package aiassist

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Engine orchestrates AI assistance with strict resource and authority budgets.
type Engine struct {
	cfg      Config
	provider Provider
}

// NewEngine creates an assistance engine with safe defaults and bounded fallback.
func NewEngine(cfg Config, p Provider) *Engine {
	if p == nil {
		p = &OfflineProvider{}
	}
	return &Engine{
		cfg:      cfg,
		provider: p,
	}
}

// CheckAssistanceEnabled verifies if the assistant is configured and permitted to run.
func (e *Engine) CheckAssistanceEnabled() error {
	if !e.cfg.Enabled || !e.cfg.OptIn {
		return errors.New("AI assistance is disabled; requires explicit opt-in configuration")
	}
	return nil
}

func (e *Engine) executeWithTimeout(
	ctx context.Context,
	req AssistanceRequest,
) (*AssistanceResponse, error) {
	timeout := e.cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	wrappedDiff, redRecords := WrapUntrustedContent(req.DiffSnippet, e.cfg.MaxContextBytes)
	req.DiffSnippet = wrappedDiff

	resp, err := e.provider.GenerateAdvice(execCtx, req)
	if err != nil {
		return nil, fmt.Errorf("assistant provider failure: %w", err)
	}

	if resp == nil {
		return nil, errors.New("empty assistant response")
	}

	resp.Redactions = append(resp.Redactions, redRecords...)
	ApplyBoundaryGuards(resp)
	return resp, nil
}

func (e *Engine) dispatch(
	ctx context.Context,
	task TaskKind,
	findings []FindingSummary,
	diff string,
) (*AssistanceResponse, error) {
	if err := e.CheckAssistanceEnabled(); err != nil {
		return nil, err
	}
	req := AssistanceRequest{
		Task:        task,
		Findings:    findings,
		DiffSnippet: diff,
		BudgetBytes: e.cfg.MaxContextBytes,
	}
	return e.executeWithTimeout(ctx, req)
}

// ExplainFindings requests contextual assistance and evidence linking for findings.
func (e *Engine) ExplainFindings(
	ctx context.Context,
	findings []FindingSummary,
) (*AssistanceResponse, error) {
	return e.dispatch(ctx, TaskExplainFinding, findings, "")
}

// SummarizeReview generates a natural-language executive summary of findings.
func (e *Engine) SummarizeReview(
	ctx context.Context,
	findings []FindingSummary,
	diffSnippet string,
) (*AssistanceResponse, error) {
	return e.dispatch(ctx, TaskSummarizeReview, findings, diffSnippet)
}

// HypothesizeCoverage analyzes code diffs to surface prospective analyzer coverage gaps.
func (e *Engine) HypothesizeCoverage(
	ctx context.Context,
	diffSnippet string,
) (*AssistanceResponse, error) {
	return e.dispatch(ctx, TaskHypothesizeCoverage, nil, diffSnippet)
}

// SuggestTriage offers heuristic triage prioritization suggestions for developer triage.
func (e *Engine) SuggestTriage(
	ctx context.Context,
	findings []FindingSummary,
) (*AssistanceResponse, error) {
	return e.dispatch(ctx, TaskSuggestTriage, findings, "")
}

// ProposeRemediation drafts a safe patch and regression test for explicit developer approval.
func (e *Engine) ProposeRemediation(
	ctx context.Context,
	f FindingSummary,
	diffSnippet string,
) (*AssistanceResponse, error) {
	return e.dispatch(ctx, TaskProposeRemediation, []FindingSummary{f}, diffSnippet)
}
