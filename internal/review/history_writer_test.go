package review

import (
	"fmt"
	"path/filepath"
	"testing"
)

func TestAppendHistoryPreservesEntries(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	entry1 := HistoryEntry{
		RunID:        "run-001",
		Status:       "failed",
		FindingCount: 2,
		Summary:      "Review failed. Findings require attention.",
	}

	if err := AppendHistory(historyPath, entry1); err != nil {
		t.Fatalf("AppendHistory(1) error: %v", err)
	}

	entry2 := HistoryEntry{
		RunID:        "run-002",
		Status:       "passed",
		FindingCount: 0,
		Summary:      "Review passed. No findings.",
	}

	if err := AppendHistory(historyPath, entry2); err != nil {
		t.Fatalf("AppendHistory(2) error: %v", err)
	}

	entries, err := ReadHistory(historyPath)
	if err != nil {
		t.Fatalf("ReadHistory() error: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].RunID != entry1.RunID {
		t.Errorf("first RunID = %q, want %q", entries[0].RunID, entry1.RunID)
	}

	if entries[1].RunID != entry2.RunID {
		t.Errorf("second RunID = %q, want %q", entries[1].RunID, entry2.RunID)
	}
}

func TestAppendHistoryRejectsEmptyPath(t *testing.T) {
	err := AppendHistory("", HistoryEntry{})

	if err == nil {
		t.Fatal("expected error for empty history path")
	}
}

func TestAppendHistoryConcurrency(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	done := make(chan error)
	concurrency := 10

	for i := 0; i < concurrency; i++ {
		go func(id int) {
			report := NewReport(fmt.Sprintf("run-%d", id), tempDir, "main", "sha", "basesha", "hash", "ver", nil, nil)
			entry := NewHistoryEntry(report)
			done <- AppendHistory(historyPath, entry)
		}(i)
	}

	for i := 0; i < concurrency; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent AppendHistory failed: %v", err)
		}
	}

	entries, err := ReadHistory(historyPath)
	if err != nil {
		t.Fatalf("ReadHistory() error: %v", err)
	}

	if len(entries) != concurrency {
		t.Fatalf("expected %d entries, got %d", concurrency, len(entries))
	}
}
