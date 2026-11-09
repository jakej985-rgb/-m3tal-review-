package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestCLI_ValidateReport(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Valid report test
	runID, err := review.NewRunID()
	if err != nil {
		t.Fatalf("failed to generate runID: %v", err)
	}
	rep := review.NewReport(runID, "repo", "main", "c1", "c0", "d1", "1.0", []string{"a.go"}, nil)
	reportPath := filepath.Join(tmpDir, runID+".json")
	if err := review.WriteReport(reportPath, rep); err != nil {
		t.Fatalf("failed to write report: %v", err)
	}

	out, err := captureOutput(func() error {
		return Run([]string{"validate-report", reportPath})
	})
	if err != nil {
		t.Fatalf("expected validate-report to succeed, got error: %v, out:\n%s", err, out)
	}
	if !strings.Contains(out, "PASS") || !strings.Contains(out, runID) {
		t.Errorf("expected output to contain PASS and runID, got:\n%s", out)
	}

	// 2. JSON format test
	outJSON, err := captureOutput(func() error {
		return Run([]string{"validate-report", reportPath, "--format", "json"})
	})
	if err != nil {
		t.Fatalf("expected validate-report --format json to succeed, got error: %v", err)
	}
	if !strings.Contains(outJSON, `"valid": true`) || !strings.Contains(outJSON, runID) {
		t.Errorf("expected JSON to contain valid: true and runID, got:\n%s", outJSON)
	}

	// 3. Invalid report test
	invalidPath := filepath.Join(tmpDir, "broken.json")
	if err := os.WriteFile(invalidPath, []byte(`{"run_id":"not-valid"}`), 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	_, err = captureOutput(func() error {
		return Run([]string{"validate-report", invalidPath})
	})
	if err == nil {
		t.Errorf("expected validate-report on invalid file to fail")
	}

	// 4. Invalid report with --format json
	outInvalidJSON, err := captureOutput(func() error {
		return Run([]string{"validate-report", invalidPath, "--format", "json"})
	})
	if err == nil {
		t.Errorf("expected validate-report on invalid file to fail with --format json")
	}
	if !strings.Contains(outInvalidJSON, `"valid": false`) {
		t.Errorf("expected invalid JSON output to contain valid: false, got:\n%s", outInvalidJSON)
	}

	// 5. Help flag
	outHelp, err := captureOutput(func() error {
		return Run([]string{"validate-report", "--help"})
	})
	if err != nil {
		t.Errorf("expected --help to succeed: %v", err)
	}
	if !strings.Contains(outHelp, "Usage:") {
		t.Errorf("expected help output, got:\n%s", outHelp)
	}

	// 6. Missing path
	_, err = captureOutput(func() error {
		return Run([]string{"validate-report"})
	})
	if err == nil {
		t.Errorf("expected missing path to fail")
	}
}
