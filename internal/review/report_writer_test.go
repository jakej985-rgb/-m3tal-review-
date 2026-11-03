package review

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteReport(t *testing.T) {
	tempDir := t.TempDir()
	reportPath := filepath.Join(tempDir, "reports", "review.json")

	report := NewReport(
		"run-001",
		tempDir,
		"main",
		"sha",
		"basesha",
		"hash",
		"ver",
		nil,
		nil,
	)

	if err := WriteReport(reportPath, report); err != nil {
		t.Fatalf("WriteReport() error: %v", err)
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report file: %v", err)
	}

	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode report JSON: %v", err)
	}

	if decoded.RunID != report.RunID {
		t.Errorf("RunID = %q, want %q", decoded.RunID, report.RunID)
	}

	if decoded.Passed != report.Passed {
		t.Errorf("Passed = %v, want %v", decoded.Passed, report.Passed)
	}

	if decoded.Summary != report.Summary {
		t.Errorf("Summary = %q, want %q", decoded.Summary, report.Summary)
	}
}

func TestWriteReportRejectsEmptyPath(t *testing.T) {
	err := WriteReport("", Report{})

	if err == nil {
		t.Fatal("expected error for empty report path")
	}
}

func TestWriteReportFailureCleanup(t *testing.T) {
	tempDir := t.TempDir()

	// Create a directory where the report file should go, but make it read-only
	// so the rename operation fails, ensuring we can test cleanup of the temp file.
	reportsDir := filepath.Join(tempDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("create reports dir: %v", err)
	}

	reportPath := filepath.Join(reportsDir, "review.json")

	// Pre-create a directory at the target file path to force a rename failure
	if err := os.Mkdir(reportPath, 0755); err != nil {
		t.Fatalf("create blocking dir: %v", err)
	}

	report := NewReport("run-001", tempDir, "main", "sha", "basesha", "hash", "ver", nil, nil)

	err := WriteReport(reportPath, report)
	if err == nil {
		t.Fatal("expected WriteReport to fail due to target path being a directory")
	}

	// Verify that no temporary files were left behind in the reports directory
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		t.Fatalf("read reports dir: %v", err)
	}

	for _, entry := range entries {
		if entry.Name() != "review.json" {
			t.Errorf("found unexpected file in reports directory: %s", entry.Name())
		}
	}
}

func TestWriteReportConcurrency(t *testing.T) {
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")

	done := make(chan error)
	concurrency := 10

	for i := 0; i < concurrency; i++ {
		go func(id int) {
			reportPath := filepath.Join(reportsDir, "review-shared.json")
			report := NewReport("run-001", tempDir, "main", "sha", "basesha", "hash", "ver", nil, nil)
			done <- WriteReport(reportPath, report)
		}(i)
	}

	for i := 0; i < concurrency; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent WriteReport failed: %v", err)
		}
	}
}

func TestWriteReportInjectedFailures(t *testing.T) {
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")
	reportPath := filepath.Join(reportsDir, "test-report.json")
	report := NewReport("0123456789abcdef", tempDir, "main", "sha", "", "", "1.0.0", nil, nil)

	// Helper to check no temp files remain
	assertNoTempFiles := func(label string) {
		entries, _ := os.ReadDir(reportsDir)
		for _, e := range entries {
			if e.Name() != "test-report.json" {
				t.Errorf("[%s] temporary file was not cleaned up: %s", label, e.Name())
			}
		}
	}

	// 1. Injected syncFile failure
	t.Run("syncFile failure", func(t *testing.T) {
		orig := syncFileHook
		defer func() { syncFileHook = orig }()
		syncFileHook = func(f *os.File) error {
			return fmt.Errorf("injected sync failure")
		}

		err := WriteReport(reportPath, report)
		if err == nil || !strings.Contains(err.Error(), "injected sync failure") {
			t.Fatalf("expected injected sync error, got: %v", err)
		}
		assertNoTempFiles("syncFile failure")
	})

	// 2. Injected closeFile failure
	t.Run("closeFile failure", func(t *testing.T) {
		orig := closeFileHook
		defer func() { closeFileHook = orig }()
		closeFileHook = func(f *os.File) error {
			_ = f.Close()
			return fmt.Errorf("injected close failure")
		}

		err := WriteReport(reportPath, report)
		if err == nil || !strings.Contains(err.Error(), "injected close failure") {
			t.Fatalf("expected injected close error, got: %v", err)
		}
		assertNoTempFiles("closeFile failure")
	})

	// 3. Injected renameFile failure
	t.Run("renameFile failure", func(t *testing.T) {
		orig := renameFileHook
		defer func() { renameFileHook = orig }()
		renameFileHook = func(oldpath, newpath string) error {
			return fmt.Errorf("injected rename failure")
		}

		err := WriteReport(reportPath, report)
		if err == nil || !strings.Contains(err.Error(), "injected rename failure") {
			t.Fatalf("expected injected rename error, got: %v", err)
		}
		assertNoTempFiles("renameFile failure")
	})

	// 4. Injected syncDir failure is non-fatal warning
	t.Run("syncDir failure is non-fatal warning", func(t *testing.T) {
		orig := syncDirHook
		defer func() { syncDirHook = orig }()
		syncDirHook = func(dir string) error {
			return fmt.Errorf("injected dir sync failure")
		}

		// Capture stderr
		r, w, _ := os.Pipe()
		origStderr := os.Stderr
		os.Stderr = w

		err := WriteReport(reportPath, report)

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
			t.Fatalf("expected WriteReport to succeed despite directory sync failure, got: %v", err)
		}
		if !strings.Contains(buf.String(), "Warning: failed to sync report directory") {
			t.Errorf("expected warning in stderr, got: %s", buf.String())
		}
		if _, statErr := os.Stat(reportPath); statErr != nil {
			t.Errorf("expected report to be successfully written, but stat failed: %v", statErr)
		}
	})
}
