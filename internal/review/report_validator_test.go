package review

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReportValidator_ValidReport(t *testing.T) {
	tmpDir := t.TempDir()
	runID, err := NewRunID()
	if err != nil {
		t.Fatalf("failed to generate run ID: %v", err)
	}

	finding := Finding{
		Rule:     "test-rule",
		Category: "security",
		Severity: "high",
		File:     "main.go",
		Line:     10,
		Message:  "Potential security issue",
	}
	findings := AssignFindingIDs([]Finding{finding})

	report := NewReport(
		runID,
		"m3tal-review",
		"main",
		"abc1234",
		"def5678",
		"hash999",
		"1.0.0",
		[]string{"main.go"},
		findings,
	)
	report.Checks = []CheckResult{
		{Name: "vet", Category: "linter", Status: "passed"},
	}

	reportPath := filepath.Join(tmpDir, runID+".json")
	if err := WriteReport(reportPath, report); err != nil {
		t.Fatalf("failed to write report: %v", err)
	}

	// Capture hash to verify non-modification
	beforeData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read before failed: %v", err)
	}
	beforeHash := sha256.Sum256(beforeData)

	res := ValidateReportFile(reportPath)
	if !res.Valid {
		t.Fatalf("expected report to be valid, got errors: %+v", res.Errors)
	}
	if res.FindingCount != 1 {
		t.Errorf("expected 1 finding, got %d", res.FindingCount)
	}
	if res.CheckCount != 1 {
		t.Errorf("expected 1 check, got %d", res.CheckCount)
	}

	// Verify file was not modified
	afterData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read after failed: %v", err)
	}
	afterHash := sha256.Sum256(afterData)
	if beforeHash != afterHash {
		t.Errorf("report file was modified during validation!")
	}
}

func TestReportValidator_DirectoryValidation(t *testing.T) {
	tmpDir := t.TempDir()
	reportsDir := filepath.Join(tmpDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	for i := 0; i < 3; i++ {
		runID, err := NewRunID()
		if err != nil {
			t.Fatalf("run ID failed: %v", err)
		}
		rep := NewReport(runID, "repo", "main", "c1", "c0", "d1", "1.0", []string{"a.go"}, nil)
		repPath := filepath.Join(reportsDir, runID+".json")
		if err := WriteReport(repPath, rep); err != nil {
			t.Fatalf("write report failed: %v", err)
		}
	}

	summary := ValidateReportTarget(reportsDir)
	if !summary.Valid {
		t.Fatalf("expected all reports valid, got errors: %+v", summary.Results)
	}
	if summary.TotalReports != 3 || summary.ValidReports != 3 || summary.InvalidReports != 0 {
		t.Errorf("unexpected summary counts: total=%d, valid=%d, invalid=%d", summary.TotalReports, summary.ValidReports, summary.InvalidReports)
	}
}

func TestReportValidator_SchemaVersion(t *testing.T) {
	runID, _ := NewRunID()
	rep := NewReport(runID, "repo", "main", "c1", "c0", "d1", "1.0", []string{"a.go"}, nil)

	// Valid versions
	for _, v := range []string{"", "1.0", "1.0.0", "v1"} {
		rep.SchemaVersion = v
		res := ValidateReport(rep, "")
		if !res.Valid {
			t.Errorf("expected schema_version %q to be valid, got errors: %+v", v, res.Errors)
		}
	}

	// Unsupported version
	rep.SchemaVersion = "99.0.0"
	res := ValidateReport(rep, "")
	if res.Valid {
		t.Errorf("expected schema_version 99.0.0 to fail validation")
	}
	found := false
	for _, e := range res.Errors {
		if e.Field == "schema_version" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error field schema_version, got %+v", res.Errors)
	}
}

func TestReportValidator_RequiredFields(t *testing.T) {
	runID, _ := NewRunID()

	// 1. Missing run_id
	rep := NewReport(runID, "repo", "main", "c1", "c0", "d1", "1.0", []string{"a.go"}, nil)
	rep.RunID = ""
	res := ValidateReport(rep, "")
	if res.Valid {
		t.Errorf("expected missing run_id to fail")
	}

	// 2. Invalid run_id format
	rep.RunID = "not-hex-1234"
	res = ValidateReport(rep, "")
	if res.Valid {
		t.Errorf("expected invalid run_id format to fail")
	}

	// 3. Zero timestamp
	rep.RunID = runID
	rep.Timestamp = time.Time{}
	res = ValidateReport(rep, "")
	if res.Valid {
		t.Errorf("expected zero timestamp to fail")
	}

	// 4. Empty repository
	rep.Timestamp = time.Now().UTC()
	rep.Repository = ""
	res = ValidateReport(rep, "")
	if res.Valid {
		t.Errorf("expected empty repository to fail")
	}

	// 5. Empty summary
	rep.Repository = "repo"
	rep.Summary = ""
	res = ValidateReport(rep, "")
	if res.Valid {
		t.Errorf("expected empty summary to fail")
	}

	// 6. Empty tool_version
	rep.Summary = "Summary"
	rep.ToolVersion = ""
	res = ValidateReport(rep, "")
	if res.Valid {
		t.Errorf("expected empty tool_version to fail")
	}
}

func TestReportValidator_RunIDPathAgreement(t *testing.T) {
	runID1, _ := NewRunID()
	runID2, _ := NewRunID()

	rep := NewReport(runID1, "repo", "main", "c1", "c0", "d1", "1.0", []string{"a.go"}, nil)

	// Matching path
	matchingPath := filepath.Join("/tmp", runID1+".json")
	res := ValidateReport(rep, matchingPath)
	if !res.Valid {
		t.Errorf("expected matching path to be valid, got %+v", res.Errors)
	}

	// Mismatched path where filename is another runID
	mismatchPath := filepath.Join("/tmp", runID2+".json")
	res = ValidateReport(rep, mismatchPath)
	if res.Valid {
		t.Errorf("expected mismatched run_id in filename to fail")
	}

	// Canonical report directory path check: /path/to/reports/non_canonical.json
	reportsDirPath := filepath.Join("/repo/.m3tal-review/reports", "other-name.json")
	res = ValidateReport(rep, reportsDirPath)
	if res.Valid {
		t.Errorf("expected non-canonical filename in reports dir to fail")
	}
}

func TestReportValidator_FindingsValidation(t *testing.T) {
	runID, _ := NewRunID()

	// Valid finding
	f1 := Finding{
		ID:       "0123456789abcdef",
		Rule:     "rule-1",
		Severity: "medium",
		Category: "security",
		File:     "foo.go",
		Line:     5,
		Message:  "Warning message",
	}

	rep := NewReport(runID, "repo", "main", "c1", "c0", "d1", "1.0", []string{"foo.go"}, []Finding{f1})
	res := ValidateReport(rep, "")
	if !res.Valid {
		t.Errorf("expected valid finding to pass, got %+v", res.Errors)
	}

	// Invalid severity
	fBadSeverity := f1
	fBadSeverity.Severity = "extreme"
	rep.Findings = []Finding{fBadSeverity}
	res = ValidateReport(rep, "")
	if res.Valid {
		t.Errorf("expected invalid severity to fail")
	}

	// Invalid category
	fBadCategory := f1
	fBadCategory.Category = "unknown-cat"
	rep.Findings = []Finding{fBadCategory}
	res = ValidateReport(rep, "")
	if res.Valid {
		t.Errorf("expected invalid category to fail")
	}

	// Empty ID
	fEmptyID := f1
	fEmptyID.ID = ""
	rep.Findings = []Finding{fEmptyID}
	res = ValidateReport(rep, "")
	if res.Valid {
		t.Errorf("expected empty ID to fail")
	}

	// Invalid non-hex ID
	fNonHexID := f1
	fNonHexID.ID = "zzzzzzzzzzzzzzzz"
	rep.Findings = []Finding{fNonHexID}
	res = ValidateReport(rep, "")
	if res.Valid {
		t.Errorf("expected non-hex ID to fail")
	}

	// Negative line
	fNegLine := f1
	fNegLine.Line = -1
	rep.Findings = []Finding{fNegLine}
	res = ValidateReport(rep, "")
	if res.Valid {
		t.Errorf("expected negative line to fail")
	}

	// Empty rule / file / message
	fEmptyRule := f1
	fEmptyRule.Rule = ""
	rep.Findings = []Finding{fEmptyRule}
	res = ValidateReport(rep, "")
	if res.Valid {
		t.Errorf("expected empty rule to fail")
	}

	// Duplicate finding IDs
	fDup1 := f1
	fDup2 := f1
	rep.Findings = []Finding{fDup1, fDup2}
	res = ValidateReport(rep, "")
	if res.Valid {
		t.Errorf("expected duplicate finding IDs to fail")
	}
}

func TestReportValidator_CheckStatuses(t *testing.T) {
	runID, _ := NewRunID()
	rep := NewReport(runID, "repo", "main", "c1", "c0", "d1", "1.0", []string{"foo.go"}, nil)

	// Valid check statuses
	for _, status := range []string{"passed", "failed", "skipped", "warning", "error", "ok", "warn"} {
		rep.Checks = []CheckResult{{Name: "c1", Category: "lint", Status: status}}
		res := ValidateReport(rep, "")
		if !res.Valid {
			t.Errorf("expected status %q to be valid, got %+v", status, res.Errors)
		}
	}

	// Invalid check status
	rep.Checks = []CheckResult{{Name: "c1", Category: "lint", Status: "running"}}
	res := ValidateReport(rep, "")
	if res.Valid {
		t.Errorf("expected invalid check status to fail")
	}

	// Empty check name
	rep.Checks = []CheckResult{{Name: "", Category: "lint", Status: "passed"}}
	res = ValidateReport(rep, "")
	if res.Valid {
		t.Errorf("expected empty check name to fail")
	}
}

func TestReportValidator_MalformedJSON(t *testing.T) {
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "bad.json")
	if err := os.WriteFile(badFile, []byte("{not valid json"), 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	res := ValidateReportFile(badFile)
	if res.Valid {
		t.Errorf("expected malformed JSON to fail")
	}

	// Non-existent file
	resNoFile := ValidateReportFile(filepath.Join(tmpDir, "missing.json"))
	if resNoFile.Valid {
		t.Errorf("expected missing file to fail")
	}
}

func TestReportValidator_DirectoryTargetSummary(t *testing.T) {
	tmpDir := t.TempDir()
	reportsDir := filepath.Join(tmpDir, "reports")
	_ = os.MkdirAll(reportsDir, 0755)

	// Add 1 valid report
	runID, _ := NewRunID()
	rep := NewReport(runID, "repo", "main", "c1", "c0", "d1", "1.0", []string{"a.go"}, nil)
	_ = WriteReport(filepath.Join(reportsDir, runID+".json"), rep)

	// Add 1 invalid report
	_ = os.WriteFile(filepath.Join(reportsDir, "invalid.json"), []byte(`{"run_id":"not-valid"}`), 0644)

	summary := ValidateReportTarget(reportsDir)
	if summary.Valid {
		t.Errorf("expected overall summary to be invalid")
	}
	if summary.TotalReports != 2 || summary.ValidReports != 1 || summary.InvalidReports != 1 {
		t.Errorf("unexpected counts: total=%d, valid=%d, invalid=%d", summary.TotalReports, summary.ValidReports, summary.InvalidReports)
	}

	// Marshal summary to verify JSON format
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if len(data) == 0 {
		t.Errorf("expected non-empty JSON data")
	}
}
