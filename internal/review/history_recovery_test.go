package review

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestRecoverHistorySerializesConcurrentAppend(t *testing.T) {
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")
	historyPath := filepath.Join(tempDir, "history.jsonl")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatal(err)
	}
	report := Report{RunID: "abcdef0123456789", Timestamp: time.Now().UTC(), Passed: true}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reportsDir, report.RunID+".json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	recoveryWriting := make(chan struct{})
	releaseRecovery := make(chan struct{})
	ops := fsOps{
		writeFile: func(file *os.File, data []byte) (int, error) {
			close(recoveryWriting)
			<-releaseRecovery
			return file.Write(data)
		},
	}
	recoveryDone := make(chan error, 1)
	go func() {
		_, err := recoverHistoryWithFS(reportsDir, historyPath, ops)
		recoveryDone <- err
	}()
	<-recoveryWriting

	appendDone := make(chan error, 1)
	go func() {
		appendDone <- AppendHistory(historyPath, HistoryEntry{RunID: "concurrent-entry", Status: "passed"})
	}()
	select {
	case err := <-appendDone:
		t.Fatalf("append completed during locked recovery: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseRecovery)
	if err := <-recoveryDone; err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	if err := <-appendDone; err != nil {
		t.Fatalf("append failed: %v", err)
	}

	entries, err := ReadHistory(historyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("history lost a recovered or appended entry: %+v", entries)
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

	existingData := []byte("original history\n")
	if err := os.WriteFile(historyPath, existingData, 0644); err != nil {
		t.Fatal(err)
	}
	if count, err := RecoverHistory(reportsDir, historyPath); err == nil || count != 0 {
		t.Fatalf("RecoverHistory() = (%d, %v), want error and no replacement", count, err)
	}
	got, err := os.ReadFile(historyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(existingData) {
		t.Fatalf("history changed after invalid report: %q", got)
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
	if err == nil || count != 0 {
		t.Fatalf("RecoverHistory() = (%d, %v), want error and no replacement", count, err)
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

func TestRecoverHistoryDuplicateRunIDs(t *testing.T) {
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")
	historyPath := filepath.Join(tempDir, "history.jsonl")

	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("failed to create reportsDir: %v", err)
	}

	runID := "0123456789abcdef"
	t1 := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 2, 11, 0, 0, 0, time.UTC)

	// Canonical report named <runID>.json with newer timestamp
	canonicalRep := Report{
		RunID:     runID,
		Timestamp: t2,
		Passed:    true,
		Summary:   "canonical report",
	}
	canonicalData, _ := json.Marshal(canonicalRep)
	if err := os.WriteFile(filepath.Join(reportsDir, runID+".json"), canonicalData, 0644); err != nil {
		t.Fatal(err)
	}

	// Duplicate report with different filename and older timestamp
	dupRep := Report{
		RunID:     runID,
		Timestamp: t1,
		Passed:    false,
		Summary:   "duplicate report",
	}
	dupData, _ := json.Marshal(dupRep)
	if err := os.WriteFile(filepath.Join(reportsDir, "backup_"+runID+".json"), dupData, 0644); err != nil {
		t.Fatal(err)
	}

	count, err := RecoverHistory(reportsDir, historyPath)
	if err != nil {
		t.Fatalf("RecoverHistory error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 recovered entry (duplicates resolved), got %d", count)
	}

	entries, err := ReadHistory(historyPath)
	if err != nil {
		t.Fatalf("ReadHistory error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(entries))
	}
	if entries[0].RunID != runID {
		t.Errorf("expected RunID = %s, got %s", runID, entries[0].RunID)
	}
	if entries[0].Summary != "canonical report" {
		t.Errorf("expected canonical report to win, got summary: %q", entries[0].Summary)
	}
}

func TestRecoverHistoryInjectedFailures(t *testing.T) {
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")
	historyPath := filepath.Join(tempDir, "history.jsonl")

	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatal(err)
	}

	validReport := Report{
		RunID:     "0123456789abcdef",
		Timestamp: time.Now().UTC(),
		Passed:    true,
	}
	validData, _ := json.Marshal(validReport)
	if err := os.WriteFile(filepath.Join(reportsDir, "0123456789abcdef.json"), validData, 0644); err != nil {
		t.Fatal(err)
	}

	origHistory := []byte("original history content\n")

	assertNoTempFilesAndHistoryPreserved := func(label string) {
		matches, _ := filepath.Glob(filepath.Join(tempDir, "history-recovery-*.tmp"))
		if len(matches) > 0 {
			t.Errorf("[%s] temporary file was not cleaned up: %v", label, matches)
		}
		data, err := os.ReadFile(historyPath)
		if err != nil {
			t.Fatalf("[%s] failed to read history file: %v", label, err)
		}
		if !bytes.Equal(data, origHistory) {
			t.Errorf("[%s] original history was not preserved! got: %s", label, string(data))
		}
	}

	// 1. Injected syncFile failure
	t.Run("syncFile failure preserves history and cleans up", func(t *testing.T) {
		if err := os.WriteFile(historyPath, origHistory, 0644); err != nil {
			t.Fatal(err)
		}

		ops := fsOps{
			syncFile: func(f *os.File) error {
				return fmt.Errorf("injected sync failure")
			},
		}

		_, err := recoverHistoryWithFS(reportsDir, historyPath, ops)
		if err == nil || !strings.Contains(err.Error(), "injected sync failure") {
			t.Fatalf("expected injected sync failure, got: %v", err)
		}
		assertNoTempFilesAndHistoryPreserved("syncFile failure")
	})

	// 2. Injected closeFile failure
	t.Run("closeFile failure preserves history and cleans up", func(t *testing.T) {
		if err := os.WriteFile(historyPath, origHistory, 0644); err != nil {
			t.Fatal(err)
		}

		ops := fsOps{
			closeFile: func(f *os.File) error {
				_ = f.Close()
				return fmt.Errorf("injected close failure")
			},
		}

		_, err := recoverHistoryWithFS(reportsDir, historyPath, ops)
		if err == nil || !strings.Contains(err.Error(), "injected close failure") {
			t.Fatalf("expected injected close failure, got: %v", err)
		}
		assertNoTempFilesAndHistoryPreserved("closeFile failure")
	})

	// 3. Injected renameFile failure
	t.Run("renameFile failure preserves history and cleans up", func(t *testing.T) {
		if err := os.WriteFile(historyPath, origHistory, 0644); err != nil {
			t.Fatal(err)
		}

		ops := fsOps{
			renameFile: func(oldpath, newpath string) error {
				return fmt.Errorf("injected rename failure")
			},
		}

		_, err := recoverHistoryWithFS(reportsDir, historyPath, ops)
		if err == nil || !strings.Contains(err.Error(), "injected rename failure") {
			t.Fatalf("expected injected rename failure, got: %v", err)
		}
		assertNoTempFilesAndHistoryPreserved("renameFile failure")
	})

	// 4. Injected syncDir failure is non-fatal warning
	t.Run("syncDir failure is non-fatal warning", func(t *testing.T) {
		ops := fsOps{
			syncDir: func(dir string) error {
				return fmt.Errorf("injected sync dir failure")
			},
		}

		r, w, _ := os.Pipe()
		origStderr := os.Stderr
		os.Stderr = w

		count, err := recoverHistoryWithFS(reportsDir, historyPath, ops)

		os.Stderr = origStderr
		_ = w.Close()
		var buf strings.Builder
		b := make([]byte, 1024)
		for {
			n, rerr := r.Read(b)
			buf.Write(b[:n])
			if rerr != nil {
				break
			}
		}
		_ = r.Close()

		if err != nil {
			t.Fatalf("expected recoverHistoryWithFS to succeed despite directory sync failure, got: %v", err)
		}
		if count != 1 {
			t.Fatalf("expected 1 entry recovered, got %d", count)
		}
		if !strings.Contains(buf.String(), "Warning: failed to sync history directory") {
			t.Errorf("expected warning in stderr, got: %s", buf.String())
		}
	})
}

func TestRecoverHistoryPrecedenceCanonicalOlderWins(t *testing.T) {
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")
	historyPath := filepath.Join(tempDir, "history.jsonl")
	_ = os.MkdirAll(reportsDir, 0755)

	runID := "aabbccddeeff0011"
	tOlder := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	tNewer := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)

	// Canonical report has older timestamp
	canonicalRep := Report{RunID: runID, Timestamp: tOlder, Passed: true, Summary: "canonical older"}
	canonicalData, _ := json.Marshal(canonicalRep)
	_ = os.WriteFile(filepath.Join(reportsDir, runID+".json"), canonicalData, 0644)

	// Backup report has newer timestamp
	backupRep := Report{RunID: runID, Timestamp: tNewer, Passed: false, Summary: "backup newer"}
	backupData, _ := json.Marshal(backupRep)
	_ = os.WriteFile(filepath.Join(reportsDir, "backup.json"), backupData, 0644)

	r, w, _ := os.Pipe()
	origStderr := os.Stderr
	os.Stderr = w

	count, err := RecoverHistory(reportsDir, historyPath)

	os.Stderr = origStderr
	_ = w.Close()
	var buf strings.Builder
	b := make([]byte, 1024)
	for {
		n, rerr := r.Read(b)
		buf.Write(b[:n])
		if rerr != nil {
			break
		}
	}
	_ = r.Close()

	if err != nil {
		t.Fatalf("RecoverHistory error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 entry, got %d", count)
	}
	entries, _ := ReadHistory(historyPath)
	if entries[0].Summary != "canonical older" {
		t.Errorf("canonical older report should win over newer backup, got: %q", entries[0].Summary)
	}

	warning := buf.String()
	if !strings.Contains(warning, "selected "+runID+".json over backup.json") || !strings.Contains(warning, "canonical filename") {
		t.Errorf("expected warning identifying selection and canonical reason, got: %s", warning)
	}
}

func TestRecoverHistoryPrecedenceCanonicalNewerWins(t *testing.T) {
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")
	historyPath := filepath.Join(tempDir, "history.jsonl")
	_ = os.MkdirAll(reportsDir, 0755)

	runID := "aabbccddeeff0022"
	tOlder := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	tNewer := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)

	// Canonical report has newer timestamp
	canonicalRep := Report{RunID: runID, Timestamp: tNewer, Passed: true, Summary: "canonical newer"}
	canonicalData, _ := json.Marshal(canonicalRep)
	_ = os.WriteFile(filepath.Join(reportsDir, runID+".json"), canonicalData, 0644)

	// Backup report has older timestamp
	backupRep := Report{RunID: runID, Timestamp: tOlder, Passed: false, Summary: "backup older"}
	backupData, _ := json.Marshal(backupRep)
	_ = os.WriteFile(filepath.Join(reportsDir, "backup.json"), backupData, 0644)

	r, w, _ := os.Pipe()
	origStderr := os.Stderr
	os.Stderr = w

	count, err := RecoverHistory(reportsDir, historyPath)

	os.Stderr = origStderr
	_ = w.Close()
	var buf strings.Builder
	b := make([]byte, 1024)
	for {
		n, rerr := r.Read(b)
		buf.Write(b[:n])
		if rerr != nil {
			break
		}
	}
	_ = r.Close()

	if err != nil {
		t.Fatalf("RecoverHistory error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 entry, got %d", count)
	}
	entries, _ := ReadHistory(historyPath)
	if entries[0].Summary != "canonical newer" {
		t.Errorf("canonical newer report should win over older backup, got: %q", entries[0].Summary)
	}

	warning := buf.String()
	if !strings.Contains(warning, "selected "+runID+".json over backup.json") || !strings.Contains(warning, "canonical filename") {
		t.Errorf("expected warning identifying selection and canonical reason, got: %s", warning)
	}
}

func TestRecoverHistoryPrecedenceEqualTimestampBackups(t *testing.T) {
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")
	historyPath := filepath.Join(tempDir, "history.jsonl")
	_ = os.MkdirAll(reportsDir, 0755)

	runID := "aabbccddeeff0033"
	tSame := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)

	// Two backup files with identical timestamp
	repA := Report{RunID: runID, Timestamp: tSame, Passed: true, Summary: "from backup_a"}
	dataA, _ := json.Marshal(repA)
	_ = os.WriteFile(filepath.Join(reportsDir, "backup_a.json"), dataA, 0644)

	repB := Report{RunID: runID, Timestamp: tSame, Passed: false, Summary: "from backup_b"}
	dataB, _ := json.Marshal(repB)
	_ = os.WriteFile(filepath.Join(reportsDir, "backup_b.json"), dataB, 0644)

	r, w, _ := os.Pipe()
	origStderr := os.Stderr
	os.Stderr = w

	count, err := RecoverHistory(reportsDir, historyPath)

	os.Stderr = origStderr
	_ = w.Close()
	var buf strings.Builder
	b := make([]byte, 1024)
	for {
		n, rerr := r.Read(b)
		buf.Write(b[:n])
		if rerr != nil {
			break
		}
	}
	_ = r.Close()

	if err != nil {
		t.Fatalf("RecoverHistory error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 entry, got %d", count)
	}
	entries, _ := ReadHistory(historyPath)
	if entries[0].Summary != "from backup_a" {
		t.Errorf("lexicographically smaller filename backup_a should win, got: %q", entries[0].Summary)
	}

	warning := buf.String()
	if !strings.Contains(warning, "selected backup_a.json over backup_b.json") || !strings.Contains(warning, "filename order") {
		t.Errorf("expected warning identifying tie-break by filename order, got: %s", warning)
	}
}

func TestRecoverHistoryPrecedenceMultipleBackupsNewerWins(t *testing.T) {
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")
	historyPath := filepath.Join(tempDir, "history.jsonl")
	_ = os.MkdirAll(reportsDir, 0755)

	runID := "aabbccddeeff0044"
	t1 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)

	rep1 := Report{RunID: runID, Timestamp: t1, Passed: false, Summary: "backup 1"}
	data1, _ := json.Marshal(rep1)
	_ = os.WriteFile(filepath.Join(reportsDir, "backup_1.json"), data1, 0644)

	rep2 := Report{RunID: runID, Timestamp: t3, Passed: true, Summary: "backup 2 newest"}
	data2, _ := json.Marshal(rep2)
	_ = os.WriteFile(filepath.Join(reportsDir, "backup_2.json"), data2, 0644)

	rep3 := Report{RunID: runID, Timestamp: t2, Passed: false, Summary: "backup 3 middle"}
	data3, _ := json.Marshal(rep3)
	_ = os.WriteFile(filepath.Join(reportsDir, "backup_3.json"), data3, 0644)

	r, w, _ := os.Pipe()
	origStderr := os.Stderr
	os.Stderr = w

	count, err := RecoverHistory(reportsDir, historyPath)

	os.Stderr = origStderr
	_ = w.Close()
	var buf strings.Builder
	b := make([]byte, 1024)
	for {
		n, rerr := r.Read(b)
		buf.Write(b[:n])
		if rerr != nil {
			break
		}
	}
	_ = r.Close()

	if err != nil {
		t.Fatalf("RecoverHistory error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 entry, got %d", count)
	}
	entries, _ := ReadHistory(historyPath)
	if entries[0].Summary != "backup 2 newest" {
		t.Errorf("newest timestamp backup should win, got: %q", entries[0].Summary)
	}

	warning := buf.String()
	if !strings.Contains(warning, "selected backup_2.json") || !strings.Contains(warning, "newer timestamp") {
		t.Errorf("expected warning identifying newer timestamp reason, got: %s", warning)
	}
}

func TestRecoverHistoryDeterminismRepeated(t *testing.T) {
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")
	historyPath := filepath.Join(tempDir, "history.jsonl")
	_ = os.MkdirAll(reportsDir, 0755)

	// Create 10 distinct reports with various timestamps
	for i := 0; i < 10; i++ {
		runID := fmt.Sprintf("%016x", i+1)
		ts := time.Date(2026, 11, 1, (i*3)%24, 0, 0, 0, time.UTC)
		rep := Report{
			RunID:     runID,
			Timestamp: ts,
			Passed:    i%2 == 0,
			Summary:   fmt.Sprintf("report %d", i),
		}
		data, _ := json.Marshal(rep)
		_ = os.WriteFile(filepath.Join(reportsDir, runID+".json"), data, 0644)

		// Add an older backup duplicate for each to test resolution under repetition
		olderTS := ts.Add(-1 * time.Hour)
		backupRep := Report{
			RunID:     runID,
			Timestamp: olderTS,
			Passed:    false,
			Summary:   fmt.Sprintf("backup report %d", i),
		}
		bdata, _ := json.Marshal(backupRep)
		_ = os.WriteFile(filepath.Join(reportsDir, "backup_"+runID+".json"), bdata, 0644)
	}

	var firstRunContent []byte
	for iteration := 0; iteration < 10; iteration++ {
		count, err := RecoverHistory(reportsDir, historyPath)
		if err != nil {
			t.Fatalf("run %d failed: %v", iteration, err)
		}
		if count != 10 {
			t.Fatalf("run %d: expected 10 entries, got %d", iteration, count)
		}

		content, err := os.ReadFile(historyPath)
		if err != nil {
			t.Fatalf("run %d read failed: %v", iteration, err)
		}

		if iteration == 0 {
			firstRunContent = content
		} else {
			if !bytes.Equal(content, firstRunContent) {
				t.Fatalf("run %d output differs from first run!\nExpected:\n%s\nGot:\n%s", iteration, string(firstRunContent), string(content))
			}
		}
	}
}
