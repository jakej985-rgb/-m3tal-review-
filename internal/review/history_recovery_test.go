package review

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecoverHistorySuccess(t *testing.T) {
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")
	historyPath := filepath.Join(tempDir, "history.jsonl")

	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("failed to create reportsDir: %v", err)
	}

	t1 := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 2, 11, 0, 0, 0, time.UTC)

	rep1 := Report{
		RunID:     "1111111111111111",
		Timestamp: t2, // later time
		Passed:    false,
		Findings: []Finding{
			{Rule: "debug-leftover", Severity: "medium", File: "main.go", Line: 10, Message: "debug"},
		},
	}
	rep2 := Report{
		RunID:     "2222222222222222",
		Timestamp: t1, // earlier time
		Passed:    true,
		Findings:  []Finding{},
	}

	data1, _ := json.Marshal(rep1)
	data2, _ := json.Marshal(rep2)

	if err := os.WriteFile(filepath.Join(reportsDir, "1111111111111111.json"), data1, 0644); err != nil {
		t.Fatalf("failed to write rep1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(reportsDir, "2222222222222222.json"), data2, 0644); err != nil {
		t.Fatalf("failed to write rep2: %v", err)
	}

	count, err := RecoverHistory(reportsDir, historyPath)
	if err != nil {
		t.Fatalf("RecoverHistory error: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 recovered entries, got %d", count)
	}

	entries, err := ReadHistory(historyPath)
	if err != nil {
		t.Fatalf("ReadHistory error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(entries))
	}
	// Entries should be sorted chronologically: t1 (rep2) then t2 (rep1)
	if entries[0].RunID != "2222222222222222" {
		t.Errorf("expected first entry to be 2222222222222222, got %s", entries[0].RunID)
	}
	if entries[1].RunID != "1111111111111111" {
		t.Errorf("expected second entry to be 1111111111111111, got %s", entries[1].RunID)
	}
}

func TestRecoverHistoryCorruptReportFiles(t *testing.T) {
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")
	historyPath := filepath.Join(tempDir, "history.jsonl")

	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("failed to create reportsDir: %v", err)
	}

	validReport := Report{
		RunID:     "abcdef0123456789",
		Timestamp: time.Now().UTC(),
		Passed:    true,
	}
	validData, _ := json.Marshal(validReport)
	if err := os.WriteFile(filepath.Join(reportsDir, "valid.json"), validData, 0644); err != nil {
		t.Fatalf("failed to write valid.json: %v", err)
	}

	// Corrupt JSON
	if err := os.WriteFile(filepath.Join(reportsDir, "corrupt.json"), []byte("{invalid-json"), 0644); err != nil {
		t.Fatalf("failed to write corrupt.json: %v", err)
	}

	// Invalid RunID
	invalidRunReport := Report{
		RunID:     "../invalid/run",
		Timestamp: time.Now().UTC(),
		Passed:    true,
	}
	invalidRunData, _ := json.Marshal(invalidRunReport)
	if err := os.WriteFile(filepath.Join(reportsDir, "invalid_run.json"), invalidRunData, 0644); err != nil {
		t.Fatalf("failed to write invalid_run.json: %v", err)
	}

	// Zero timestamp
	zeroTimeReport := Report{
		RunID:     "0011223344556677",
		Timestamp: time.Time{},
		Passed:    true,
	}
	zeroTimeData, _ := json.Marshal(zeroTimeReport)
	if err := os.WriteFile(filepath.Join(reportsDir, "zero_time.json"), zeroTimeData, 0644); err != nil {
		t.Fatalf("failed to write zero_time.json: %v", err)
	}

	count, err := RecoverHistory(reportsDir, historyPath)
	if err != nil {
		t.Fatalf("RecoverHistory error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 recovered entry, got %d", count)
	}

	entries, err := ReadHistory(historyPath)
	if err != nil {
		t.Fatalf("ReadHistory error: %v", err)
	}
	if len(entries) != 1 || entries[0].RunID != "abcdef0123456789" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestRecoverHistoryPreservesExistingOnNoValidReports(t *testing.T) {
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")
	historyPath := filepath.Join(tempDir, "history.jsonl")

	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("failed to create reportsDir: %v", err)
	}

	// Existing history with some data
	existingData := []byte(`{"run_id":"abcdef0123456789","timestamp":"2026-11-01T00:00:00Z","status":"passed","finding_count":0,"summary":"ok"}` + "\n")
	if err := os.WriteFile(historyPath, existingData, 0644); err != nil {
		t.Fatalf("failed to write existing history: %v", err)
	}

	// Reports directory contains only corrupt report
	if err := os.WriteFile(filepath.Join(reportsDir, "corrupt.json"), []byte("not-json"), 0644); err != nil {
		t.Fatalf("failed to write corrupt.json: %v", err)
	}

	count, err := RecoverHistory(reportsDir, historyPath)
	if err != nil {
		t.Fatalf("RecoverHistory error: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 recovered entries, got %d", count)
	}

	content, err := os.ReadFile(historyPath)
	if err != nil {
		t.Fatalf("failed to read history: %v", err)
	}
	if string(content) != string(existingData) {
		t.Fatalf("expected original history to be preserved, got %q", string(content))
	}
}

func TestRecoverHistoryWriteFailure(t *testing.T) {
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("failed to create reportsDir: %v", err)
	}

	validReport := Report{
		RunID:     "abcdef0123456789",
		Timestamp: time.Now().UTC(),
		Passed:    true,
	}
	validData, _ := json.Marshal(validReport)
	if err := os.WriteFile(filepath.Join(reportsDir, "valid.json"), validData, 0644); err != nil {
		t.Fatalf("failed to write valid.json: %v", err)
	}

	// Create an unwritable history dir
	readOnlyDir := filepath.Join(tempDir, "readonly")
	if err := os.MkdirAll(readOnlyDir, 0555); err != nil {
		t.Fatalf("failed to create readonly dir: %v", err)
	}
	t.Cleanup(func() {
		os.Chmod(readOnlyDir, 0755)
	})

	historyPath := filepath.Join(readOnlyDir, "history.jsonl")

	_, err := RecoverHistory(reportsDir, historyPath)
	if err == nil {
		t.Fatalf("expected error when history directory is not writable")
	}
}

func TestRecoverHistoryReplacementFailure(t *testing.T) {
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("failed to create reportsDir: %v", err)
	}

	validReport := Report{
		RunID:     "abcdef0123456789",
		Timestamp: time.Now().UTC(),
		Passed:    true,
	}
	validData, _ := json.Marshal(validReport)
	if err := os.WriteFile(filepath.Join(reportsDir, "valid.json"), validData, 0644); err != nil {
		t.Fatalf("failed to write valid.json: %v", err)
	}

	// historyPath is an existing directory, so os.Rename(tempFile, historyPath) fails on POSIX
	dirAsHistoryPath := filepath.Join(tempDir, "is_a_directory")
	if err := os.MkdirAll(dirAsHistoryPath, 0755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	_, err := RecoverHistory(reportsDir, dirAsHistoryPath)
	if err == nil {
		t.Fatalf("expected error when destination is a directory")
	}

	// Verify temp file was cleaned up
	matches, _ := filepath.Glob(filepath.Join(tempDir, "history-recovery-*.tmp"))
	if len(matches) > 0 {
		t.Fatalf("expected temp file to be cleaned up on failure, found: %v", matches)
	}
}
