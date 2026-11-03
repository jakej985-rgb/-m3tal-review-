package review

import (
	"bytes"
	"errors"
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
	ops := fsOps{
		syncDir: func(dir string) error {
			syncedDir = dir
			return nil
		},
	}

	entry := HistoryEntry{
		RunID:        "run-new-001",
		Status:       "passed",
		FindingCount: 0,
		Summary:      "New file entry.",
	}

	if err := appendHistoryWithFS(historyPath, entry, ops); err != nil {
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

	ops := fsOps{
		syncDir: func(dir string) error {
			return fmt.Errorf("injected dir sync failure")
		},
	}

	entry := HistoryEntry{
		RunID:        "run-warn-001",
		Status:       "passed",
		FindingCount: 0,
		Summary:      "Directory sync warning test",
	}

	stderrOutput := captureStderr(t, func() {
		err := appendHistoryWithFS(historyPath, entry, ops)
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
	ops := fsOps{
		syncFile: func(f *os.File) error {
			return fmt.Errorf("injected sync failure")
		},
	}

	entry2 := HistoryEntry{
		RunID:        "run-failed-sync",
		Status:       "failed",
		FindingCount: 1,
		Summary:      "Should not be appended",
	}

	err := appendHistoryWithFS(historyPath, entry2, ops)
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

	ops := fsOps{
		closeFile: func(f *os.File) error {
			_ = f.Close()
			return fmt.Errorf("injected close failure")
		},
	}

	entry := HistoryEntry{
		RunID:        "run-close-fail",
		Status:       "passed",
		FindingCount: 0,
		Summary:      "Close fail test",
	}

	err := appendHistoryWithFS(historyPath, entry, ops)
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

// Phase 1 Tests: History Rollback Integrity

type customTestError struct {
	tag string
}

func (e *customTestError) Error() string {
	return "custom error: " + e.tag
}

func TestAppendHistoryWriteFailureWithRollback(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	entry1 := HistoryEntry{RunID: "run-001", Status: "passed", FindingCount: 0, Summary: "Initial"}
	if err := AppendHistory(historyPath, entry1); err != nil {
		t.Fatalf("setup AppendHistory failed: %v", err)
	}

	errWrite := &customTestError{tag: "disk write failed"}
	ops := fsOps{
		writeFile: func(f *os.File, b []byte) (int, error) {
			return 0, errWrite
		},
	}

	entry2 := HistoryEntry{RunID: "run-002", Status: "failed", FindingCount: 1, Summary: "Failed append"}
	err := appendHistoryWithFS(historyPath, entry2, ops)

	if err == nil {
		t.Fatal("expected append error, got nil")
	}
	if !errors.Is(err, errWrite) {
		t.Fatalf("expected error to wrap original write failure, got: %v", err)
	}

	entries, err := ReadHistory(historyPath)
	if err != nil {
		t.Fatalf("ReadHistory failed: %v", err)
	}
	if len(entries) != 1 || entries[0].RunID != entry1.RunID {
		t.Fatalf("expected existing history preserved intact, got: %+v", entries)
	}
}

func TestAppendHistoryFileSyncFailureWithRollback(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	entry1 := HistoryEntry{RunID: "run-001", Status: "passed", FindingCount: 0, Summary: "Initial"}
	if err := AppendHistory(historyPath, entry1); err != nil {
		t.Fatalf("setup AppendHistory failed: %v", err)
	}

	errSync := &customTestError{tag: "fsync failed"}
	ops := fsOps{
		syncFile: func(f *os.File) error {
			return errSync
		},
	}

	entry2 := HistoryEntry{RunID: "run-002", Status: "failed", FindingCount: 1, Summary: "Failed append"}
	err := appendHistoryWithFS(historyPath, entry2, ops)

	if err == nil {
		t.Fatal("expected sync error, got nil")
	}
	if !errors.Is(err, errSync) {
		t.Fatalf("expected error to wrap original sync failure, got: %v", err)
	}

	entries, err := ReadHistory(historyPath)
	if err != nil {
		t.Fatalf("ReadHistory failed: %v", err)
	}
	if len(entries) != 1 || entries[0].RunID != entry1.RunID {
		t.Fatalf("expected existing history preserved intact, got: %+v", entries)
	}
}

func TestAppendHistoryCloseFailureWithRollback(t *testing.T) {
	t.Run("existing file close failure rolls back successfully", func(t *testing.T) {
		tempDir := t.TempDir()
		historyPath := filepath.Join(tempDir, "history.jsonl")

		entry1 := HistoryEntry{RunID: "run-001", Status: "passed", FindingCount: 0, Summary: "Initial"}
		if err := AppendHistory(historyPath, entry1); err != nil {
			t.Fatalf("setup AppendHistory failed: %v", err)
		}

		errClose := &customTestError{tag: "close failed"}
		closeCount := 0
		ops := fsOps{
			closeFile: func(f *os.File) error {
				closeCount++
				_ = f.Close()
				if closeCount == 1 {
					return errClose
				}
				return nil
			},
		}

		entry2 := HistoryEntry{RunID: "run-002", Status: "failed", FindingCount: 1, Summary: "Failed append"}
		err := appendHistoryWithFS(historyPath, entry2, ops)

		if err == nil {
			t.Fatal("expected close error, got nil")
		}
		if !errors.Is(err, errClose) {
			t.Fatalf("expected error to wrap original close failure, got: %v", err)
		}

		entries, err := ReadHistory(historyPath)
		if err != nil {
			t.Fatalf("ReadHistory failed: %v", err)
		}
		if len(entries) != 1 || entries[0].RunID != entry1.RunID {
			t.Fatalf("expected existing history preserved intact, got: %+v", entries)
		}
	})

	t.Run("new file close failure removes file successfully", func(t *testing.T) {
		tempDir := t.TempDir()
		historyPath := filepath.Join(tempDir, "history.jsonl")

		errClose := &customTestError{tag: "close failed"}
		ops := fsOps{
			closeFile: func(f *os.File) error {
				_ = f.Close()
				return errClose
			},
		}

		entry := HistoryEntry{RunID: "run-new", Status: "passed", FindingCount: 0, Summary: "New file"}
		err := appendHistoryWithFS(historyPath, entry, ops)

		if err == nil {
			t.Fatal("expected close error, got nil")
		}
		if !errors.Is(err, errClose) {
			t.Fatalf("expected error to wrap original close failure, got: %v", err)
		}

		if _, statErr := os.Stat(historyPath); !os.IsNotExist(statErr) {
			t.Fatalf("expected new history file to be removed after failed append, got err: %v", statErr)
		}
	})
}

func TestAppendHistoryTruncateFailure(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	entry1 := HistoryEntry{RunID: "run-001", Status: "passed", FindingCount: 0, Summary: "Initial"}
	if err := AppendHistory(historyPath, entry1); err != nil {
		t.Fatalf("setup AppendHistory failed: %v", err)
	}

	errWrite := &customTestError{tag: "write failed"}
	errTruncate := &customTestError{tag: "truncate failed"}

	ops := fsOps{
		writeFile: func(f *os.File, b []byte) (int, error) {
			return 0, errWrite
		},
		truncateFile: func(f *os.File, size int64) error {
			return errTruncate
		},
	}

	entry2 := HistoryEntry{RunID: "run-002", Status: "failed", FindingCount: 1, Summary: "Failed append"}
	err := appendHistoryWithFS(historyPath, entry2, ops)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errWrite) {
		t.Errorf("expected error to retain original write error, got: %v", err)
	}
	if !errors.Is(err, errTruncate) {
		t.Errorf("expected error to retain rollback truncate error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "rollback truncate") {
		t.Errorf("expected 'rollback truncate' in error string, got: %v", err)
	}
}

func TestAppendHistoryRollbackSyncFailure(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	entry1 := HistoryEntry{RunID: "run-001", Status: "passed", FindingCount: 0, Summary: "Initial"}
	if err := AppendHistory(historyPath, entry1); err != nil {
		t.Fatalf("setup AppendHistory failed: %v", err)
	}

	errWrite := &customTestError{tag: "write failed"}
	errRollbackSync := &customTestError{tag: "rollback sync failed"}

	ops := fsOps{
		writeFile: func(f *os.File, b []byte) (int, error) {
			return 0, errWrite
		},
		syncFile: func(f *os.File) error {
			return errRollbackSync
		},
	}

	entry2 := HistoryEntry{RunID: "run-002", Status: "failed", FindingCount: 1, Summary: "Failed append"}
	err := appendHistoryWithFS(historyPath, entry2, ops)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errWrite) {
		t.Errorf("expected error to retain original write error, got: %v", err)
	}
	if !errors.Is(err, errRollbackSync) {
		t.Errorf("expected error to retain rollback sync error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "rollback sync") {
		t.Errorf("expected 'rollback sync' in error string, got: %v", err)
	}
}

func TestAppendHistoryRemoveFailureAfterFailedCreation(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	errWrite := &customTestError{tag: "write failed"}
	errRemove := &customTestError{tag: "remove failed"}

	ops := fsOps{
		writeFile: func(f *os.File, b []byte) (int, error) {
			return 0, errWrite
		},
		removeFile: func(name string) error {
			return errRemove
		},
	}

	entry := HistoryEntry{RunID: "run-new", Status: "passed", FindingCount: 0, Summary: "New file"}
	err := appendHistoryWithFS(historyPath, entry, ops)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errWrite) {
		t.Errorf("expected error to retain original write error, got: %v", err)
	}
	if !errors.Is(err, errRemove) {
		t.Errorf("expected error to retain rollback remove error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "rollback remove") {
		t.Errorf("expected 'rollback remove' in error string, got: %v", err)
	}
}

func TestAppendHistoryErrorCausality(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	rootCauseWrite := &customTestError{tag: "root cause disk full"}
	rootCauseRollback := &customTestError{tag: "root cause bad sector truncate"}

	ops := fsOps{
		writeFile: func(f *os.File, b []byte) (int, error) {
			return 0, rootCauseWrite
		},
		truncateFile: func(f *os.File, size int64) error {
			return rootCauseRollback
		},
	}

	// Create file so rollback attempts truncate
	if err := AppendHistory(historyPath, HistoryEntry{RunID: "run-root"}); err != nil {
		t.Fatal(err)
	}

	err := appendHistoryWithFS(historyPath, HistoryEntry{RunID: "run-fail"}, ops)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, rootCauseWrite) {
		t.Errorf("errors.Is failed to find rootCauseWrite in: %v", err)
	}
	if !errors.Is(err, rootCauseRollback) {
		t.Errorf("errors.Is failed to find rootCauseRollback in: %v", err)
	}

	var target *customTestError
	if !errors.As(err, &target) {
		t.Errorf("errors.As failed to extract *customTestError from: %v", err)
	}
}

// Phase 1: File Existence Detection Tests

func TestAppendHistoryStatFileDetection(t *testing.T) {
	t.Run("existing history file detected", func(t *testing.T) {
		tempDir := t.TempDir()
		historyPath := filepath.Join(tempDir, "history.jsonl")

		entry1 := HistoryEntry{RunID: "run-exist-1", Status: "passed"}
		if err := AppendHistory(historyPath, entry1); err != nil {
			t.Fatalf("setup AppendHistory failed: %v", err)
		}

		statCalled := false
		ops := fsOps{
			statFile: func(name string) (os.FileInfo, error) {
				statCalled = true
				return os.Stat(name)
			},
		}

		entry2 := HistoryEntry{RunID: "run-exist-2", Status: "passed"}
		if err := appendHistoryWithFS(historyPath, entry2, ops); err != nil {
			t.Fatalf("expected append to succeed on existing file, got: %v", err)
		}

		if !statCalled {
			t.Fatal("expected statFile to be called")
		}

		entries, err := ReadHistory(historyPath)
		if err != nil {
			t.Fatalf("ReadHistory failed: %v", err)
		}
		if len(entries) != 2 {
			t.Fatalf("expected 2 entries, got %d", len(entries))
		}
	})

	t.Run("missing history file detected and created", func(t *testing.T) {
		tempDir := t.TempDir()
		historyPath := filepath.Join(tempDir, "history.jsonl")

		statCalled := false
		syncedDir := ""
		ops := fsOps{
			statFile: func(name string) (os.FileInfo, error) {
				statCalled = true
				return os.Stat(name)
			},
			syncDir: func(dir string) error {
				syncedDir = dir
				return nil
			},
		}

		entry := HistoryEntry{RunID: "run-new-file", Status: "passed"}
		if err := appendHistoryWithFS(historyPath, entry, ops); err != nil {
			t.Fatalf("expected append to create new file, got: %v", err)
		}

		if !statCalled {
			t.Fatal("expected statFile to be called")
		}
		if syncedDir != tempDir {
			t.Errorf("expected parent directory %s to be synced, got %s", tempDir, syncedDir)
		}

		entries, err := ReadHistory(historyPath)
		if err != nil {
			t.Fatalf("ReadHistory failed: %v", err)
		}
		if len(entries) != 1 || entries[0].RunID != entry.RunID {
			t.Fatalf("unexpected entries: %+v", entries)
		}
	})

	t.Run("stat permission or filesystem failure aborts immediately without modifying history", func(t *testing.T) {
		tempDir := t.TempDir()
		historyPath := filepath.Join(tempDir, "history.jsonl")

		origEntry := HistoryEntry{RunID: "run-preserve", Status: "passed", FindingCount: 0, Summary: "Original"}
		if err := AppendHistory(historyPath, origEntry); err != nil {
			t.Fatalf("setup AppendHistory failed: %v", err)
		}
		origBytes, _ := os.ReadFile(historyPath)

		errStatPermission := &customTestError{tag: "stat permission denied"}
		openCalled := false

		ops := fsOps{
			statFile: func(name string) (os.FileInfo, error) {
				return nil, errStatPermission
			},
			openFile: func(name string, flag int, perm os.FileMode) (*os.File, error) {
				openCalled = true
				return os.OpenFile(name, flag, perm)
			},
		}

		newEntry := HistoryEntry{RunID: "run-should-not-append", Status: "failed"}
		err := appendHistoryWithFS(historyPath, newEntry, ops)

		if err == nil {
			t.Fatal("expected error on stat permission failure, got nil")
		}
		if !errors.Is(err, errStatPermission) {
			t.Fatalf("expected error to wrap errStatPermission, got: %v", err)
		}
		if openCalled {
			t.Fatal("openFile should not be called when stat fails with non-NotExist error")
		}

		// Ensure original history was NOT deleted, replaced, or altered
		currentBytes, err := os.ReadFile(historyPath)
		if err != nil {
			t.Fatalf("failed to read history file: %v", err)
		}
		if !bytes.Equal(currentBytes, origBytes) {
			t.Fatalf("existing history was altered! expected %s, got %s", string(origBytes), string(currentBytes))
		}
	})
}

// Phase 2: Rollback Failure Handling Tests

func TestAppendHistoryRollbackCloseFailure(t *testing.T) {
	t.Run("existing file rollback close failure", func(t *testing.T) {
		tempDir := t.TempDir()
		historyPath := filepath.Join(tempDir, "history.jsonl")

		entry1 := HistoryEntry{RunID: "run-001", Status: "passed"}
		if err := AppendHistory(historyPath, entry1); err != nil {
			t.Fatalf("setup AppendHistory failed: %v", err)
		}

		errWrite := &customTestError{tag: "write failed"}
		errRollbackClose := &customTestError{tag: "rollback close failed"}

		ops := fsOps{
			writeFile: func(f *os.File, b []byte) (int, error) {
				return 0, errWrite
			},
			closeFile: func(f *os.File) error {
				_ = f.Close()
				return errRollbackClose
			},
		}

		entry2 := HistoryEntry{RunID: "run-002", Status: "failed"}
		err := appendHistoryWithFS(historyPath, entry2, ops)

		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, errWrite) {
			t.Errorf("expected original append error to be discoverable, got: %v", err)
		}
		if !errors.Is(err, errRollbackClose) {
			t.Errorf("expected rollback close error to be discoverable, got: %v", err)
		}
		if !strings.Contains(err.Error(), "rollback close") {
			t.Errorf("expected 'rollback close' in error message, got: %v", err)
		}
	})

	t.Run("new file rollback close failure", func(t *testing.T) {
		tempDir := t.TempDir()
		historyPath := filepath.Join(tempDir, "history.jsonl")

		errWrite := &customTestError{tag: "write failed"}
		errRollbackClose := &customTestError{tag: "rollback close failed"}

		ops := fsOps{
			writeFile: func(f *os.File, b []byte) (int, error) {
				return 0, errWrite
			},
			closeFile: func(f *os.File) error {
				_ = f.Close()
				return errRollbackClose
			},
		}

		entry := HistoryEntry{RunID: "run-new-close-fail", Status: "passed"}
		err := appendHistoryWithFS(historyPath, entry, ops)

		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, errWrite) {
			t.Errorf("expected original append error to be discoverable, got: %v", err)
		}
		if !errors.Is(err, errRollbackClose) {
			t.Errorf("expected rollback close error to be discoverable, got: %v", err)
		}
		if !strings.Contains(err.Error(), "rollback close") {
			t.Errorf("expected 'rollback close' in error message, got: %v", err)
		}
	})
}

func TestAppendHistoryReopenFailureOnRollback(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	entry1 := HistoryEntry{RunID: "run-001", Status: "passed"}
	if err := AppendHistory(historyPath, entry1); err != nil {
		t.Fatalf("setup AppendHistory failed: %v", err)
	}

	errAppendClose := &customTestError{tag: "append close failed"}
	errRollbackReopen := &customTestError{tag: "rollback reopen failed"}

	openCalls := 0
	ops := fsOps{
		openFile: func(name string, flag int, perm os.FileMode) (*os.File, error) {
			openCalls++
			if openCalls == 1 {
				// Initial open for append
				return os.OpenFile(name, flag, perm)
			}
			// Reopen attempt during rollback
			return nil, errRollbackReopen
		},
		closeFile: func(f *os.File) error {
			_ = f.Close()
			return errAppendClose
		},
	}

	entry2 := HistoryEntry{RunID: "run-002", Status: "failed"}
	err := appendHistoryWithFS(historyPath, entry2, ops)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errAppendClose) {
		t.Errorf("expected original close error to be discoverable via errors.Is, got: %v", err)
	}
	if !errors.Is(err, errRollbackReopen) {
		t.Errorf("expected rollback reopen error to be discoverable via errors.Is, got: %v", err)
	}
	if !strings.Contains(err.Error(), "rollback open") {
		t.Errorf("expected 'rollback open' in error message, got: %v", err)
	}
}
