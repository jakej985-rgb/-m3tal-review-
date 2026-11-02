package review

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadHistory(t *testing.T) {
	historyPath := filepath.Join(t.TempDir(), "history.jsonl")

	content := `{"run_id":"run-001","status":"failed","finding_count":2,"summary":"Review failed."}` + "\n" +
		`{"run_id":"run-002","status":"passed","finding_count":0,"summary":"Review passed."}` + "\n"

	if err := os.WriteFile(historyPath, []byte(content), 0644); err != nil {
		t.Fatalf("write history fixture: %v", err)
	}

	entries, err := ReadHistory(historyPath)
	if err != nil {
		t.Fatalf("ReadHistory() error: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].RunID != "run-001" {
		t.Errorf("first RunID = %q, want run-001", entries[0].RunID)
	}

	if entries[0].Status != "failed" {
		t.Errorf("first Status = %q, want failed", entries[0].Status)
	}

	if entries[1].RunID != "run-002" {
		t.Errorf("second RunID = %q, want run-002", entries[1].RunID)
	}

	if entries[1].Status != "passed" {
		t.Errorf("second Status = %q, want passed", entries[1].Status)
	}
}

func TestReadHistoryMissingFile(t *testing.T) {
	historyPath := filepath.Join(t.TempDir(), "missing.jsonl")

	entries, err := ReadHistory(historyPath)
	if err != nil {
		t.Fatalf("expected missing file to return no error, got: %v", err)
	}

	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}
