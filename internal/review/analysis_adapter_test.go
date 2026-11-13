package review

import (
	"encoding/json"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
)

func TestAnalysisFindingFromReviewDefaults(t *testing.T) {
	f := Finding{
		ID:          "abcdef0123456789",
		Rule:        "sql-injection",
		Severity:    "high",
		Confidence:  "medium",
		File:        "src/db.go",
		Line:        42,
		Message:     "user input reaches query",
		Remediation: "use parameterized queries",
		Snippet:     "db.Query(q)",
		Evidence: []FindingEvidence{
			{Rule: "request-taint", Line: 10, Message: "tainted source"},
			{Analyzer: "taint", Line: 42, Message: "sink reached"},
		},
	}

	got := AnalysisFindingFromReview(f)

	if got.Status != analysis.StatusPotential {
		t.Fatalf("legacy findings must default to potential, got %q", got.Status)
	}
	if got.RuleID != "sql-injection" {
		t.Fatalf("rule_id = %q", got.RuleID)
	}
	if got.Confidence != analysis.ConfidenceMedium {
		t.Fatalf("confidence = %q", got.Confidence)
	}
	if got.LegacyID != "abcdef0123456789" {
		t.Fatalf("legacy ID not preserved: %q", got.LegacyID)
	}
	if len(got.Spans) != 1 || got.Spans[0].File != "src/db.go" || got.Spans[0].StartLine != 42 {
		t.Fatalf("bad spans: %+v", got.Spans)
	}
	if len(got.Evidence) != 2 {
		t.Fatalf("expected 2 evidence steps, got %d", len(got.Evidence))
	}
	if got.Evidence[0].Kind != analysis.EvidenceNote {
		t.Fatalf("legacy evidence should map to note steps, got %q", got.Evidence[0].Kind)
	}
	if got.Evidence[1].Span.StartLine != 42 {
		t.Fatalf("evidence line not mapped: %+v", got.Evidence[1].Span)
	}
	if got.ID == "" || len(got.ID) != 16 {
		t.Fatalf("expected derived 16-hex ID, got %q", got.ID)
	}
}

func TestAnalysisFindingFromReviewStatusOverride(t *testing.T) {
	f := Finding{
		Rule:     "r",
		Severity: "low",
		File:     "a.go",
		Line:     1,
		Message:  "m",
		Metadata: map[string]string{
			"analysis_status":             "unverified",
			"analysis_truncated":          "true",
			"analysis_truncation_reasons": "max-paths",
		},
	}
	got := AnalysisFindingFromReview(f)
	if got.Status != analysis.StatusUnverified {
		t.Fatalf("status override not applied: %q", got.Status)
	}
	if got.Truncation.Complete() {
		t.Fatal("expected incomplete truncation")
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("unverified+truncated should validate: %v", err)
	}
}

func TestAnalysisFindingFromReviewProvenDowngradedWhenTruncated(t *testing.T) {
	f := Finding{
		Rule:     "r",
		Severity: "low",
		File:     "a.go",
		Line:     1,
		Message:  "m",
		Metadata: map[string]string{
			"analysis_status":    "proven",
			"analysis_truncated": "yes",
		},
	}
	got := AnalysisFindingFromReview(f)
	if got.Status == analysis.StatusProven {
		t.Fatal("proven claim with declared truncation must be downgraded")
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("downgraded finding should validate: %v", err)
	}
}

func TestAnalysisFindingFromReviewIDDeterminism(t *testing.T) {
	f := Finding{Rule: "r", Severity: "low", File: "a.go", Line: 3, Message: "m"}
	a := AnalysisFindingFromReview(f)
	b := AnalysisFindingFromReview(f)
	if a.ID != b.ID {
		t.Fatalf("adapter IDs not deterministic: %s vs %s", a.ID, b.ID)
	}
}

func TestAnalysisReportFromReview(t *testing.T) {
	report := Report{
		SchemaVersion:   "1.0.0",
		RunID:           "0123456789abcdef",
		ToolVersion:     "9.9.9",
		ReviewedFiles:   []string{"a.go", "b.go"},
		UnanalyzedFiles: []string{"c.go"},
		Findings: []Finding{{
			Rule: "r", Severity: "medium", File: "a.go", Line: 7, Message: "m",
		}},
	}
	ar := AnalysisReportFromReview(report)

	if ar.SchemaVersion != analysis.CurrentSchemaVersion {
		t.Fatalf("schema = %q", ar.SchemaVersion)
	}
	if len(ar.Findings) != 1 || ar.Findings[0].Status != analysis.StatusPotential {
		t.Fatalf("unexpected findings: %+v", ar.Findings)
	}
	if len(ar.Runs) != 1 || ar.Runs[0].ID != report.RunID {
		t.Fatalf("run metadata lost: %+v", ar.Runs)
	}
	if len(ar.Diagnostics) != 1 || ar.Diagnostics[0].Category != analysis.DiagUnsupported {
		t.Fatalf("unanalyzed files should surface as diagnostics: %+v", ar.Diagnostics)
	}
	if err := ar.Validate(); err != nil {
		t.Fatalf("adapted report invalid: %v", err)
	}

	data, err := json.Marshal(ar)
	if err != nil {
		t.Fatalf("marshal adapted report: %v", err)
	}
	if _, err := analysis.ReadJSON(data); err != nil {
		t.Fatalf("adapted report not readable: %v", err)
	}
}

func TestLegacyReportJSONUnchanged(t *testing.T) {
	// The legacy report schema must remain readable and writable
	// unchanged; the analysis contract is additive.
	r := NewReport("0123456789abcdef", "repo", "main", "sha", "", "dh", "1.0.0",
		[]string{"a.go"},
		[]Finding{{Rule: "r", Severity: "low", File: "a.go", Line: 1, Message: "m"}},
	)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal legacy report: %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("legacy report round-trip: %v", err)
	}
	if decoded.SchemaVersion != "1.0.0" {
		t.Fatalf("legacy schema version changed: %q", decoded.SchemaVersion)
	}
}
