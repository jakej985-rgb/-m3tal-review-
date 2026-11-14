package review

import (
	"path/filepath"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
)

func TestReviewFindingFromAnalysis(t *testing.T) {
	af := analysis.Finding{
		ID:          "0123456789abcdef",
		RuleID:      "typestate-double-consume",
		Analyzer:    "typestate",
		Message:     "challenge consumed twice",
		Severity:    "high",
		Status:      analysis.StatusProven,
		Trace:       analysis.TraceStateTransition,
		Remediation: "consume once",
		Spans: []analysis.Span{{
			File:      filepath.Join("repo", "main.go"),
			StartLine: 10,
			EndLine:   12,
		}},
		Evidence: []analysis.EvidenceStep{
			{Kind: analysis.EvidenceState, Note: "first consume", Span: analysis.SingleLineSpan("repo/main.go", 10)},
			{Kind: analysis.EvidenceSink, Entity: &analysis.EntityRef{Kind: analysis.EntityFunction, ID: "fn1", Name: "Consume"}},
		},
	}

	root := filepath.Join("repo")
	f := ReviewFindingFromAnalysis(af, root)

	if f.Category != "semantic" {
		t.Fatalf("Category = %q, want semantic", f.Category)
	}
	if f.Rule != "typestate-double-consume" {
		t.Fatalf("Rule = %q", f.Rule)
	}
	if f.ID != af.ID {
		t.Fatalf("ID = %q, want preserved %q", f.ID, af.ID)
	}
	if len(f.Analyzers) != 1 || f.Analyzers[0] != "typestate" {
		t.Fatalf("Analyzers = %v", f.Analyzers)
	}
	if f.Line != 10 {
		t.Fatalf("Line = %d, want 10", f.Line)
	}
	if f.Metadata["analysis_status"] != "proven" {
		t.Fatalf("analysis_status = %q", f.Metadata["analysis_status"])
	}
	if f.Metadata["analysis_trace"] != "state-transition" {
		t.Fatalf("analysis_trace = %q", f.Metadata["analysis_trace"])
	}
	if len(f.Evidence) != 2 {
		t.Fatalf("Evidence len = %d, want 2", len(f.Evidence))
	}
	if f.Evidence[1].Message != "sink Consume" {
		t.Fatalf("evidence entity message = %q, want %q", f.Evidence[1].Message, "sink Consume")
	}
}

func TestReviewFindingFromAnalysisTruncation(t *testing.T) {
	af := analysis.Finding{
		RuleID:   "concurrency-check-then-act",
		Analyzer: "concurrency",
		Message:  "check-then-act",
		Severity: "medium",
		Status:   analysis.StatusPotential,
		Truncation: analysis.Truncation{
			Truncated: true,
			Reasons:   []string{"max-traces"},
		},
		Spans: []analysis.Span{analysis.SingleLineSpan("a.go", 3)},
	}
	f := ReviewFindingFromAnalysis(af, "")
	if f.Metadata["analysis_truncated"] != "true" {
		t.Fatalf("analysis_truncated = %q", f.Metadata["analysis_truncated"])
	}
	if f.Metadata["analysis_truncation_reasons"] != "max-traces" {
		t.Fatalf("reasons = %q", f.Metadata["analysis_truncation_reasons"])
	}
	if f.Metadata["analysis_status"] != "potential" {
		t.Fatalf("status = %q", f.Metadata["analysis_status"])
	}
}

func TestRelativizeSpanFile(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "repo")
	got := relativizeSpanFile(filepath.Join(root, "sub", "f.go"), root)
	if got != "sub/f.go" {
		t.Fatalf("relativize = %q, want sub/f.go", got)
	}
	got = relativizeSpanFile("/other/f.go", root)
	if got != "/other/f.go" {
		t.Fatalf("outside path = %q, want unchanged", got)
	}
}
