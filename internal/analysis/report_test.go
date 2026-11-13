package analysis

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewReportAssignsIDsSortsAndValidates(t *testing.T) {
	mk := func(file string, line int, rule string) Finding {
		f := Finding{
			RuleID:   rule,
			Message:  "msg " + rule,
			Severity: "low",
			Status:   StatusPotential,
			Spans:    []Span{SingleLineSpan(file, line)},
		}
		return f
	}
	report := NewReport("run-1",
		[]Run{{Analyzer: "test", ToolVersion: "1.2.3"}},
		[]Finding{mk("b.go", 1, "r2"), mk("a.go", 5, "r1")},
		[]Diagnostic{{
			Severity: DiagSeverityWarning,
			Category: DiagUnsupported,
			Message:  "cgo not modeled",
		}},
	)

	if report.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("schema version = %q, want %q", report.SchemaVersion, CurrentSchemaVersion)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(report.Findings))
	}
	for _, f := range report.Findings {
		if f.ID == "" {
			t.Fatal("finding missing assigned ID")
		}
	}
	if report.Findings[0].PrimarySpan().File != "a.go" {
		t.Fatalf("findings not sorted: first file %q", report.Findings[0].PrimarySpan().File)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("NewReport produced invalid report: %v", err)
	}
}

func TestReportJSONRoundTrip(t *testing.T) {
	f := Finding{
		RuleID:   "lock-order",
		Message:  "consistent lock ordering violated",
		Severity: "medium",
		Status:   StatusProven,
		Trace:    TraceLockSequence,
		Spans:    []Span{SingleLineSpan("src/mu.go", 42)},
		Evidence: []EvidenceStep{
			{Kind: EvidenceLock, Span: SingleLineSpan("src/mu.go", 10), Note: "Lock(A)"},
			{Kind: EvidenceLock, Span: SingleLineSpan("src/mu.go", 20), Note: "Lock(B)"},
			{Kind: EvidenceLock, Span: SingleLineSpan("src/other.go", 5), Note: "Lock(A) again"},
		},
	}
	report := NewReport("run-9", nil, []Finding{f}, nil)

	data, err := report.WriteJSON()
	if err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !strings.Contains(string(data), `"schema_version": "analysis/1.0.0"`) {
		t.Fatalf("missing schema version in output: %s", data)
	}

	back, err := ReadJSON(data)
	if err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if back.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("schema version lost: %q", back.SchemaVersion)
	}
	if len(back.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(back.Findings))
	}
	got := back.Findings[0]
	if got.ID != report.Findings[0].ID {
		t.Fatalf("ID changed across round-trip: %s vs %s", got.ID, report.Findings[0].ID)
	}
	if got.Status != StatusProven || len(got.Evidence) != 3 {
		t.Fatalf("finding content lost: %+v", got)
	}
	if err := back.Validate(); err != nil {
		t.Fatalf("round-tripped report invalid: %v", err)
	}
}

func TestReportMarshalRejectsInvalidFinding(t *testing.T) {
	bad := Finding{
		RuleID:   "x",
		Message:  "x",
		Severity: "high",
		Status:   StatusProven, // no evidence -> invalid
		Spans:    []Span{SingleLineSpan("a.go", 1)},
	}
	report := Report{
		SchemaVersion: CurrentSchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Findings:      []Finding{bad.EnsureID()},
	}
	if _, err := json.Marshal(report); err == nil {
		t.Fatal("expected marshal of report with proven/evidence-free finding to fail")
	}
}

func TestReportValidateSchemaAndDiagnostics(t *testing.T) {
	r := NewReport("r", nil, nil, []Diagnostic{{
		Severity: "bogus",
		Category: DiagNote,
		Message:  "x",
	}})
	if err := r.Validate(); err == nil {
		t.Fatal("expected invalid diagnostic severity to fail validation")
	}

	r.SchemaVersion = "analysis/9.9"
	if err := r.Validate(); err == nil {
		t.Fatal("expected unsupported schema version to fail validation")
	}
}
