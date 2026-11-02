package review

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAppendHistoryPreservesEntries(t *testing.T) {
	historyPath := filepath.Join(t.TempDir(), "history", "runs.jsonl")

	first := HistoryEntry{
		RunID:        "run-001",
		Status:       "failed",
		FindingCount: 2,
		Summary:      "Review failed.",
	}

	second := HistoryEntry{
		RunID:        "run-002",
		Status:       "passed",
		FindingCount: 0,
		Summary:      "Review passed.",
	}

	if err := AppendHistory(historyPath, first); err != nil {
		t.Fatalf("append first entry: %v", err)
	}

	if err := AppendHistory(historyPath, second); err != nil {
		t.Fatalf("append second entry: %v", err)
	}

	file, err := os.Open(historyPath)
	if err != nil {
		t.Fatalf("open history file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var entries []HistoryEntry

	for scanner.Scan() {
		var entry HistoryEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("decode history entry: %v", err)
		}

		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("scan history file: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].RunID != first.RunID {
		t.Errorf("first RunID = %q, want %q", entries[0].RunID, first.RunID)
	}

	if entries[1].RunID != second.RunID {
		t.Errorf("second RunID = %q, want %q", entries[1].RunID, second.RunID)
	}
}

func TestAppendHistoryRejectsEmptyPath(t *testing.T) {
	err := AppendHistory("", HistoryEntry{})

	if err == nil {
		t.Fatal("expected error for empty history path")
	}
}
