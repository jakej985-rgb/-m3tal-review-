package review

import (
	"testing"
	"time"
)

func TestNewReportPassed(t *testing.T) {
	report := NewReport(
		"run-001",
		"/tmp/test-repo",
		"main",
		"abcd123",
		"base123",
		"diffhash",
		"1.0.0",
		[]string{"file1.go"},
		nil,
	)

	if !report.Passed {
		t.Fatal("expected report to pass with no findings")
	}

	if report.Summary != "Review passed. No findings." {
		t.Fatalf("unexpected summary: %q", report.Summary)
	}

	if report.RunID != "run-001" {
		t.Fatalf("unexpected run ID: %q", report.RunID)
	}

	if report.Repository != "/tmp/test-repo" {
		t.Fatalf("unexpected repository: %q", report.Repository)
	}

	if report.Branch != "main" {
		t.Fatalf("unexpected branch: %q", report.Branch)
	}

	if report.Timestamp.IsZero() {
		t.Fatal("expected timestamp to be set")
	}

	if report.Timestamp.Location() != time.UTC {
		t.Fatalf("expected UTC timestamp, got: %v", report.Timestamp.Location())
	}
}

func TestNewReportFailed(t *testing.T) {
	findings := []Finding{{}}

	report := NewReport(
		"run-002",
		"/tmp/test-repo",
		"feature/test",
		"abcd123",
		"base123",
		"diffhash",
		"1.0.0",
		[]string{"file1.go"},
		findings,
	)

	if report.Passed {
		t.Fatal("expected report to fail when findings exist")
	}

	if report.Summary != "Review failed. Findings require attention." {
		t.Fatalf("unexpected summary: %q", report.Summary)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
}

func TestInformationalRiskSignalDoesNotFailReport(t *testing.T) {
	report := NewReport("run-info", "/tmp/test-repo", "main", "head", "base", "hash", "1.0.0", nil, []Finding{{
		Rule: "review-risk", Category: "risk", Severity: "info", File: "internal/auth/login.go", Message: "Sensitive area changed",
	}})
	if !report.Passed {
		t.Fatal("informational risk signal should not fail the review")
	}
	if report.Summary != "Review passed with informational risk signals." {
		t.Fatalf("summary = %q", report.Summary)
	}
	if report.Findings[0].ID == "" {
		t.Fatal("finding ID was not assigned")
	}
}

func TestCompareFindingsReportsNewResolvedAndExisting(t *testing.T) {
	previous := []Finding{{Rule: "todo-marker", File: "a.go", Line: 1, Message: "TODO"}, {Rule: "debug-leftover", File: "b.go", Line: 2, Message: "debug"}}
	current := []Finding{{Rule: "todo-marker", File: "a.go", Line: 1, Message: "TODO"}, {Rule: "code-slop", File: "c.go", Line: 3, Message: "slop"}}
	changes := CompareFindings(previous, current)
	if changes.Existing != 1 || len(changes.New) != 1 || len(changes.Resolved) != 1 {
		t.Fatalf("finding changes = %+v", changes)
	}
}
