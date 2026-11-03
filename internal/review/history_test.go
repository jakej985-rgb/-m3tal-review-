package review

import (
	"testing"
	"time"
)

func TestNewHistoryEntryPassed(t *testing.T) {
	timestamp := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

	report := Report{
		RunID:     "run-pass",
		Timestamp: timestamp,
		Passed:    true,
		Summary:   "Review passed. No findings.",
		Findings:  nil,
	}

	entry := NewHistoryEntry(report)

	if entry.RunID != report.RunID {
		t.Errorf("RunID = %q, want %q", entry.RunID, report.RunID)
	}

	if entry.Status != "passed" {
		t.Errorf("Status = %q, want passed", entry.Status)
	}

	if entry.FindingCount != 0 {
		t.Errorf("FindingCount = %d, want 0", entry.FindingCount)
	}

	if !entry.Timestamp.Equal(timestamp) {
		t.Errorf("Timestamp = %v, want %v", entry.Timestamp, timestamp)
	}
}

func TestNewHistoryEntryFailed(t *testing.T) {
	report := Report{
		RunID:    "run-fail",
		Passed:   false,
		Summary:  "Review failed. Findings require attention.",
		Findings: []Finding{{}, {}},
	}

	entry := NewHistoryEntry(report)

	if entry.Status != "failed" {
		t.Errorf("Status = %q, want failed", entry.Status)
	}

	if entry.FindingCount != 2 {
		t.Errorf("FindingCount = %d, want 2", entry.FindingCount)
	}
}

func TestNewHistoryEntryIncompleteAnalysis(t *testing.T) {
	report := Report{
		RunID:           "run-incomplete",
		Passed:          false,
		UnanalyzedFiles: []string{"asset.bin"},
		Findings:        nil,
	}
	entry := NewHistoryEntry(report)
	if entry.Status != "incomplete" {
		t.Errorf("Status = %q, want incomplete", entry.Status)
	}
}
