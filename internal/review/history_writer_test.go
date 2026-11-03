package review

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	outChan := make(chan string)
	go func() {
		var buf strings.Builder
		_, _ = io.Copy(&buf, r)
		outChan <- buf.String()
	}()

	fn()

	_ = w.Close()
	os.Stderr = orig
	out := <-outChan
	_ = r.Close()
	return out
}

func TestAppendHistoryExistingFile(t *testing.T) {
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

func TestAppendHistoryNewFileCreation(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	syncedDir := ""
	setFSOpsForTest(t, fsOps{
		syncDir: func(dir string) error {
			syncedDir = dir
			return nil
		},
	})

	entry := HistoryEntry{
		RunID:        "run-new-001",
		Status:       "passed",
		FindingCount: 0,
		Summary:      "New file entry.",
	}

	if err := AppendHistory(historyPath, entry); err != nil {
		t.Fatalf("AppendHistory error: %v", err)
	}

	if syncedDir != tempDir {
		t.Errorf("expected parent directory %q to be synced, got %q", tempDir, syncedDir)
	}

	entries, err := ReadHistory(historyPath)
	if err != nil {
		t.Fatalf("ReadHistory error: %v", err)
	}
	if len(entries) != 1 || entries[0].RunID != entry.RunID {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestAppendHistoryDirectorySyncWarning(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	setFSOpsForTest(t, fsOps{
		syncDir: func(dir string) error {
			return fmt.Errorf("injected dir sync failure")
		},
	})

	entry := HistoryEntry{
		RunID:        "run-warn-001",
		Status:       "passed",
		FindingCount: 0,
		Summary:      "Directory sync warning test",
	}

	stderrOutput := captureStderr(t, func() {
		err := AppendHistory(historyPath, entry)
		if err != nil {
			t.Fatalf("expected AppendHistory to succeed despite dir sync failure, got: %v", err)
		}
	})

	if !strings.Contains(stderrOutput, "Warning: failed to sync directory") || !strings.Contains(stderrOutput, "injected dir sync failure") {
		t.Fatalf("expected directory sync warning in stderr, got: %q", stderrOutput)
	}

	// Verify the entry was still written
	entries, err := ReadHistory(historyPath)
	if err != nil {
		t.Fatalf("ReadHistory error: %v", err)
	}
	if len(entries) != 1 || entries[0].RunID != entry.RunID {
		t.Fatalf("expected 1 entry written, got: %+v", entries)
	}
}

func TestAppendHistoryFileSyncFailurePreservesExisting(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	entry1 := HistoryEntry{
		RunID:        "run-initial",
		Status:       "passed",
		FindingCount: 0,
		Summary:      "Initial entry",
	}

	if err := AppendHistory(historyPath, entry1); err != nil {
		t.Fatalf("setup AppendHistory failed: %v", err)
	}

	// Inject syncFile failure
	setFSOpsForTest(t, fsOps{
		syncFile: func(f *os.File) error {
			return fmt.Errorf("injected sync failure")
		},
	})

	entry2 := HistoryEntry{
		RunID:        "run-failed-sync",
		Status:       "failed",
		FindingCount: 1,
		Summary:      "Should not be appended",
	}

	err := AppendHistory(historyPath, entry2)
	if err == nil || !strings.Contains(err.Error(), "injected sync failure") {
		t.Fatalf("expected injected sync failure, got: %v", err)
	}

	// Verify original history file is completely intact and preserved
	entries, err := ReadHistory(historyPath)
	if err != nil {
		t.Fatalf("ReadHistory error: %v", err)
	}
	if len(entries) != 1 || entries[0].RunID != entry1.RunID {
		t.Fatalf("expected only initial entry preserved, got: %+v", entries)
	}
}

func TestAppendHistoryCloseFailure(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	setFSOpsForTest(t, fsOps{
		closeFile: func(f *os.File) error {
			_ = f.Close()
			return fmt.Errorf("injected close failure")
		},
	})

	entry := HistoryEntry{
		RunID:        "run-close-fail",
		Status:       "passed",
		FindingCount: 0,
		Summary:      "Close fail test",
	}

	err := AppendHistory(historyPath, entry)
	if err == nil || !strings.Contains(err.Error(), "injected close failure") {
		t.Fatalf("expected injected close failure, got: %v", err)
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
