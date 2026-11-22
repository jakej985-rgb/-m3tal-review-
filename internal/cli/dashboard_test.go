package cli

import (
	"html/template"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDashboardServer_RendersMetricsAndReports(t *testing.T) {
	tmpDir := t.TempDir()
	reportsDir := filepath.Join(tmpDir, ".m3tal-review", "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("failed to create reportsDir: %v", err)
	}

	dummyReport := `{
		"run_id": "1234567890abcdef",
		"branch": "main",
		"passed": true,
		"grade": {
			"grade": "A",
			"score": 95,
			"total_penalty": 5,
			"finding_counts": {"low": 1}
		},
		"findings": [
			{"rule": "code-slop", "severity": "low", "file": "main.go", "line": 10}
		]
	}`
	if err := os.WriteFile(filepath.Join(reportsDir, "1234567890abcdef.json"), []byte(dummyReport), 0644); err != nil {
		t.Fatalf("failed to write dummy report: %v", err)
	}

	data, err := LoadDashboardData(tmpDir)
	if err != nil {
		t.Fatalf("LoadDashboardData failed: %v", err)
	}

	if data.TotalReviews != 1 {
		t.Errorf("expected 1 review, got %d", data.TotalReviews)
	}
	if data.AverageGrade != "A" || data.AverageScore != 95 {
		t.Errorf("expected grade A (95), got %s (%d)", data.AverageGrade, data.AverageScore)
	}

	// Test HTML generation
	tmpl, err := template.New("dashboard").Parse(dashboardHTMLTemplate)
	if err != nil {
		t.Fatalf("template parse error: %v", err)
	}

	w := httptest.NewRecorder()
	if err := tmpl.Execute(w, data); err != nil {
		t.Fatalf("template execute error: %v", err)
	}

	respBody := w.Body.String()
	if !strings.Contains(respBody, "1234567890abcdef") {
		t.Errorf("expected rendered HTML to contain run ID, got:\n%s", respBody)
	}
	if !strings.Contains(respBody, "Average Grade") {
		t.Errorf("expected rendered HTML to contain Average Grade, got:\n%s", respBody)
	}
}
