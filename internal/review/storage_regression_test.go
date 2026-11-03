package review

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestStorageRegressionExistingHistorySurvivesFailedAppends verifies existing history survives any append failure.
func TestStorageRegressionExistingHistorySurvivesFailedAppends(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	entries := []HistoryEntry{
		{RunID: "run-001", Status: "passed", FindingCount: 0, Summary: "First"},
		{RunID: "run-002", Status: "passed", FindingCount: 0, Summary: "Second"},
		{RunID: "run-003", Status: "failed", FindingCount: 1, Summary: "Third"},
	}

	for _, e := range entries {
		if err := AppendHistory(historyPath, e); err != nil {
			t.Fatalf("setup append failed: %v", err)
		}
	}

	origBytes, err := os.ReadFile(historyPath)
	if err != nil {
		t.Fatalf("read orig bytes failed: %v", err)
	}

	badEntry := HistoryEntry{RunID: "run-bad", Status: "failed", FindingCount: 5, Summary: "Bad"}

	// 1. Write failure
	t.Run("write failure preserves history", func(t *testing.T) {
		ops := fsOps{
			writeFile: func(f *os.File, b []byte) (int, error) {
				return 0, errors.New("injected write err")
			},
		}
		err := appendHistoryWithFS(historyPath, badEntry, ops)
		if err == nil {
			t.Fatal("expected write error")
		}
		data, _ := os.ReadFile(historyPath)
		if !bytes.Equal(data, origBytes) {
			t.Fatal("history was altered after write failure")
		}
	})

	// 2. Sync failure
	t.Run("sync failure preserves history", func(t *testing.T) {
		ops := fsOps{
			syncFile: func(f *os.File) error {
				return errors.New("injected sync err")
			},
		}
		err := appendHistoryWithFS(historyPath, badEntry, ops)
		if err == nil {
			t.Fatal("expected sync error")
		}
		data, _ := os.ReadFile(historyPath)
		if !bytes.Equal(data, origBytes) {
			t.Fatal("history was altered after sync failure")
		}
	})

	// 3. Close failure
	t.Run("close failure preserves history", func(t *testing.T) {
		closeCount := 0
		ops := fsOps{
			closeFile: func(f *os.File) error {
				closeCount++
				_ = f.Close()
				if closeCount == 1 {
					return errors.New("injected close err")
				}
				return nil
			},
		}
		err := appendHistoryWithFS(historyPath, badEntry, ops)
		if err == nil {
			t.Fatal("expected close error")
		}
		data, _ := os.ReadFile(historyPath)
		if !bytes.Equal(data, origBytes) {
			t.Fatal("history was altered after close failure")
		}
	})
}

// TestStorageRegressionNewHistoryRemovedAfterFailedCreation verifies new files are removed on append failure.
func TestStorageRegressionNewHistoryRemovedAfterFailedCreation(t *testing.T) {
	tempDir := t.TempDir()

	entry := HistoryEntry{RunID: "run-create-fail", Status: "passed", FindingCount: 0, Summary: "Test"}

	// Failed write
	path1 := filepath.Join(tempDir, "history1.jsonl")
	opsWriteFail := fsOps{
		writeFile: func(f *os.File, b []byte) (int, error) {
			return 0, errors.New("write failure")
		},
	}
	_ = appendHistoryWithFS(path1, entry, opsWriteFail)
	if _, err := os.Stat(path1); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be removed after write failure, but it exists", path1)
	}

	// Failed sync
	path2 := filepath.Join(tempDir, "history2.jsonl")
	opsSyncFail := fsOps{
		syncFile: func(f *os.File) error {
			return errors.New("sync failure")
		},
	}
	_ = appendHistoryWithFS(path2, entry, opsSyncFail)
	if _, err := os.Stat(path2); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be removed after sync failure, but it exists", path2)
	}
}

// TestStorageRegressionSuccessfulAppendsValidJSONL verifies successful appends remain valid JSONL.
func TestStorageRegressionSuccessfulAppendsValidJSONL(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	for i := 0; i < 5; i++ {
		entry := HistoryEntry{
			RunID:        fmt.Sprintf("run-%03d", i),
			Timestamp:    time.Now().UTC(),
			Status:       "passed",
			FindingCount: i,
			Summary:      fmt.Sprintf("Summary %d", i),
		}
		if err := AppendHistory(historyPath, entry); err != nil {
			t.Fatalf("AppendHistory %d failed: %v", i, err)
		}
	}

	file, err := os.Open(historyPath)
	if err != nil {
		t.Fatalf("open history failed: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		lineCount++
		var parsed HistoryEntry
		if err := json.Unmarshal(line, &parsed); err != nil {
			t.Fatalf("line %d is not valid JSON (%q): %v", lineCount, string(line), err)
		}
		if parsed.RunID != fmt.Sprintf("run-%03d", lineCount-1) {
			t.Errorf("line %d has RunID %s, expected run-%03d", lineCount, parsed.RunID, lineCount-1)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}
	if lineCount != 5 {
		t.Fatalf("expected 5 lines of JSONL, got %d", lineCount)
	}
}

// TestStorageRegressionRecoveryPreservesOldFileOnPreRenameErrors verifies recovery preserves history on pre-rename errors.
func TestStorageRegressionRecoveryPreservesOldFileOnPreRenameErrors(t *testing.T) {
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")
	historyPath := filepath.Join(tempDir, "history.jsonl")

	_ = os.MkdirAll(reportsDir, 0755)
	rep := Report{
		RunID:     "1234567890abcdef",
		Timestamp: time.Now().UTC(),
		Passed:    true,
	}
	data, _ := json.Marshal(rep)
	_ = os.WriteFile(filepath.Join(reportsDir, "1234567890abcdef.json"), data, 0644)

	initialHistory := []byte(`{"run_id":"orig-001","status":"passed"}` + "\n")
	_ = os.WriteFile(historyPath, initialHistory, 0644)

	testCases := []struct {
		name string
		ops  fsOps
	}{
		{
			name: "write failure",
			ops: fsOps{
				writeFile: func(f *os.File, b []byte) (int, error) {
					return 0, errors.New("write err")
				},
			},
		},
		{
			name: "sync failure",
			ops: fsOps{
				syncFile: func(f *os.File) error {
					return errors.New("sync err")
				},
			},
		},
		{
			name: "close failure",
			ops: fsOps{
				closeFile: func(f *os.File) error {
					_ = f.Close()
					return errors.New("close err")
				},
			},
		},
		{
			name: "rename failure",
			ops: fsOps{
				renameFile: func(oldpath, newpath string) error {
					return errors.New("rename err")
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := recoverHistoryWithFS(reportsDir, historyPath, tc.ops)
			if err == nil {
				t.Fatalf("[%s] expected error", tc.name)
			}
			content, err := os.ReadFile(historyPath)
			if err != nil {
				t.Fatalf("[%s] read history failed: %v", tc.name, err)
			}
			if !bytes.Equal(content, initialHistory) {
				t.Fatalf("[%s] original history was altered! got: %s", tc.name, string(content))
			}
		})
	}
}

// TestStorageRegressionAtomicReportReplacement verifies atomic report replacement under concurrency.
func TestStorageRegressionAtomicReportReplacement(t *testing.T) {
	tempDir := t.TempDir()
	reportPath := filepath.Join(tempDir, "reports", "report.json")

	initialReport := NewReport("run-init", tempDir, "main", "sha", "", "", "1.0.0", nil, nil)
	if err := WriteReport(reportPath, initialReport); err != nil {
		t.Fatalf("initial WriteReport failed: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 5 readers continuously reading and verifying uncorrupted JSON
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					data, err := os.ReadFile(reportPath)
					if err == nil {
						var r Report
						if jsonErr := json.Unmarshal(data, &r); jsonErr != nil {
							t.Errorf("atomic report read observed torn or corrupt write: %v", jsonErr)
						}
					}
				}
			}
		}()
	}

	// 5 writers continuously updating the report atomically
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				r := NewReport(fmt.Sprintf("run-%d-%d", writerID, j), tempDir, "main", "sha", "", "", "1.0.0", nil, nil)
				if err := WriteReport(reportPath, r); err != nil {
					t.Errorf("WriteReport failed: %v", err)
				}
			}
		}(i)
	}

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestStorageRegressionTempFileCleanup verifies temporary files are cleaned up on all failure paths.
func TestStorageRegressionTempFileCleanup(t *testing.T) {
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")
	_ = os.MkdirAll(reportsDir, 0755)

	reportPath := filepath.Join(reportsDir, "report.json")
	report := NewReport("run-cleanup", tempDir, "main", "sha", "", "", "1.0.0", nil, nil)

	injectedOps := []fsOps{
		{writeFile: func(f *os.File, b []byte) (int, error) { return 0, errors.New("err") }},
		{syncFile: func(f *os.File) error { return errors.New("err") }},
		{closeFile: func(f *os.File) error { _ = f.Close(); return errors.New("err") }},
		{renameFile: func(oldpath, newpath string) error { return errors.New("err") }},
	}

	for idx, ops := range injectedOps {
		_ = writeReportWithFS(reportPath, report, ops)
		entries, _ := os.ReadDir(reportsDir)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".tmp") {
				t.Fatalf("op %d left temporary file behind: %s", idx, e.Name())
			}
		}
	}
}
