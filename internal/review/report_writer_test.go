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
