package review

import (
	"encoding/json"
	"os"
	"path/filepath"
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
