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
