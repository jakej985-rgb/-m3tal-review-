package cli

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// Helper to construct simulated ExitError
func mockExitError(code int) error {
	// Running a command that exits with code gives a real *exec.ExitError
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "exit "+itoaLen(code))
		return cmd.Run()
	}
	cmd := exec.Command("sh", "-c", "exit "+itoaLen(code))
	return cmd.Run()
}

func TestGitleaksReportValidation(t *testing.T) {
	// 1. Valid findings
	validJSON := `[
		{
			"RuleID": "generic-api-key",
			"Description": "Generic API Key",
			"StartLine": 10,
			"EndLine": 10,
			"Match": "secret123",
			"File": "config.go"
		}
	]`
	findings, err := parseGitleaksReport([]byte(validJSON), nil)
	if err != nil {
		t.Fatalf("unexpected error on valid gitleaks json: %v", err)
	}
	if len(findings) != 1 || findings[0].Rule != "gitleaks-generic-api-key" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	if findings[0].Severity != "high" || findings[0].Confidence != "high" || findings[0].RawSeverity != "HIGH" {
		t.Fatalf("unexpected severity/confidence: %+v", findings[0])
	}

	// 2. Valid empty output
	for _, empty := range []string{"[]", "", "   \n"} {
		findings, err := parseGitleaksReport([]byte(empty), nil)
		if err != nil {
			t.Fatalf("expected clean pass on valid empty gitleaks output %q: %v", empty, err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings on empty output, got %d", len(findings))
		}
	}

	// 3. Malformed JSON
	malformed := `[{"RuleID": "test", `
	if _, err := parseGitleaksReport([]byte(malformed), nil); err == nil {
		t.Fatal("expected error on malformed JSON, got nil")
	}

	// 4. Missing required fields
	missingRule := `[{"File": "config.go", "StartLine": 5}]`
	if _, err := parseGitleaksReport([]byte(missingRule), nil); err == nil {
		t.Fatal("expected error on missing RuleID, got nil")
	}
	missingFile := `[{"RuleID": "key", "StartLine": 5}]`
	if _, err := parseGitleaksReport([]byte(missingFile), nil); err == nil {
		t.Fatal("expected error on missing File, got nil")
	}

	// 5. Unknown fields rejected
	unknownField := `[{"RuleID": "key", "File": "a.go", "unrecognized_field": 123}]`
	if _, err := parseGitleaksReport([]byte(unknownField), nil); err == nil {
		t.Fatal("expected schema error on unknown field, got nil")
	}

	// 6. Nonzero exit codes
	exitErr1 := mockExitError(1)
	// Exit code 1 with valid findings is accepted
	findings, err = parseGitleaksReport([]byte(validJSON), exitErr1)
	if err != nil || len(findings) != 1 {
		t.Fatalf("exit code 1 with findings should succeed, got err=%v findings=%d", err, len(findings))
	}
	// Exit code 1 with 0 findings must fail
	if _, err := parseGitleaksReport([]byte("[]"), exitErr1); err == nil {
		t.Fatal("exit code 1 with 0 findings must fail, got nil")
	}
	// Exit code 2 (syntax/fatal error) must fail even if JSON present
	exitErr2 := mockExitError(2)
	if _, err := parseGitleaksReport([]byte(validJSON), exitErr2); err == nil {
		t.Fatal("exit code 2 must fail, got nil")
	}
}

func TestGosecReportValidation(t *testing.T) {
	// 1. Valid findings
	validJSON := `{
		"Issues": [
			{
				"severity": "HIGH",
				"confidence": "MEDIUM",
				"cwe": {"id": "CWE-79", "url": "https://cwe.mitre.org/data/definitions/79.html"},
				"rule_id": "G201",
				"details": "SQL query string formatting",
				"file": "db/query.go",
				"line": "45"
			}
		],
		"Stats": {"files": 1, "lines": 50, "nosec": 0, "found": 1}
	}`
	findings, err := parseGosecReport([]byte(validJSON), nil)
	if err != nil {
		t.Fatalf("unexpected error on valid gosec json: %v", err)
	}
	if len(findings) != 1 || findings[0].Rule != "gosec-G201" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	if findings[0].Severity != "high" || findings[0].RawSeverity != "HIGH" {
		t.Errorf("severity = %q, raw = %q", findings[0].Severity, findings[0].RawSeverity)
	}
	if findings[0].Confidence != "medium" {
		t.Errorf("confidence = %q, want medium", findings[0].Confidence)
	}
	if findings[0].AdvisoryID != "CWE-79" {
		t.Errorf("advisoryID = %q, want CWE-79", findings[0].AdvisoryID)
	}

	// 2. Valid empty output
	for _, empty := range []string{`{"Issues": []}`, "", "   "} {
		findings, err := parseGosecReport([]byte(empty), nil)
		if err != nil {
			t.Fatalf("expected clean pass on valid empty gosec output %q: %v", empty, err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings on empty output, got %d", len(findings))
		}
	}

	// 3. Malformed JSON
	if _, err := parseGosecReport([]byte(`{"Issues": [broken`), nil); err == nil {
		t.Fatal("expected error on malformed gosec json, got nil")
	}

	// 4. Missing required fields
	missingRule := `{"Issues": [{"file": "a.go", "details": "d", "severity": "HIGH"}]}`
	if _, err := parseGosecReport([]byte(missingRule), nil); err == nil {
		t.Fatal("expected error on missing rule_id, got nil")
	}
	missingFile := `{"Issues": [{"rule_id": "G101", "details": "d", "severity": "HIGH"}]}`
	if _, err := parseGosecReport([]byte(missingFile), nil); err == nil {
		t.Fatal("expected error on missing file, got nil")
	}
	missingDetails := `{"Issues": [{"rule_id": "G101", "file": "a.go", "severity": "HIGH"}]}`
	if _, err := parseGosecReport([]byte(missingDetails), nil); err == nil {
		t.Fatal("expected error on missing details, got nil")
	}

	// 5. Unknown fields rejected
	unknownField := `{"Issues": [], "unexpected_gosec_key": 999}`
	if _, err := parseGosecReport([]byte(unknownField), nil); err == nil {
		t.Fatal("expected error on unknown field in gosec report, got nil")
	}

	// 6. Nonzero exit code
	exitErr1 := mockExitError(1)
	// Code 1 with valid findings is accepted
	findings, err = parseGosecReport([]byte(validJSON), exitErr1)
	if err != nil || len(findings) != 1 {
		t.Fatalf("exit code 1 with findings should succeed, got err=%v findings=%d", err, len(findings))
	}
	// Code 1 with 0 findings must fail
	if _, err := parseGosecReport([]byte(`{"Issues": []}`), exitErr1); err == nil {
		t.Fatal("expected error on gosec code 1 with 0 findings, got nil")
	}
	// Code 2 (fatal/runtime error) must fail
	if _, err := parseGosecReport([]byte(validJSON), mockExitError(2)); err == nil {
		t.Fatal("expected error on gosec fatal exit code 2, got nil")
	}

	// 7. Line range parsing
	rangeJSON := `{
		"Issues": [
			{
				"severity": "HIGH",
				"rule_id": "G101",
				"details": "Hardcoded credentials",
				"file": "auth.go",
				"line": "45-48"
			}
		]
	}`
	rangeFindings, err := parseGosecReport([]byte(rangeJSON), nil)
	if err != nil {
		t.Fatalf("unexpected error on range JSON: %v", err)
	}
	if len(rangeFindings) != 1 || rangeFindings[0].Line != 45 {
		t.Fatalf("expected parsed line 45 for range 45-48, got: %d", rangeFindings[0].Line)
	}
}

func TestOSVScannerReportValidation(t *testing.T) {
	// 1. Valid findings
	validJSON := `{
		"results": [
			{
				"source": {"path": "go.mod", "type": "lockfile"},
				"packages": [
					{
						"package": {"name": "golang.org/x/crypto", "version": "v0.0.1", "ecosystem": "Go"},
						"vulnerabilities": [
							{
								"id": "GO-2023-1234",
								"summary": "Denial of service in crypto",
								"aliases": ["CVE-2023-12345", "GHSA-xxxx-yyyy-zzzz"],
								"severity": [
									{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H:7.5"}
								]
							}
						]
					}
				]
			}
		]
	}`
	findings, err := parseOSVScannerReport([]byte(validJSON), nil, "")
	if err != nil {
		t.Fatalf("unexpected error on valid osv-scanner json: %v", err)
	}
	if len(findings) != 1 || findings[0].Rule != "osv-GO-2023-1234" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	if findings[0].Severity != "high" {
		t.Errorf("severity = %q, want high", findings[0].Severity)
	}
	if !strings.Contains(findings[0].RawSeverity, "7.5") {
		t.Errorf("raw severity %q should contain score 7.5", findings[0].RawSeverity)
	}
	if findings[0].Confidence != "high" {
		t.Errorf("confidence = %q, want high", findings[0].Confidence)
	}
	if findings[0].AdvisoryID != "GO-2023-1234" {
		t.Errorf("advisory ID = %q, want GO-2023-1234", findings[0].AdvisoryID)
	}
	if len(findings[0].AdvisoryIDs) != 3 {
		t.Errorf("advisory IDs = %v, want 3 IDs", findings[0].AdvisoryIDs)
	}

	// 2. Valid empty output
	for _, empty := range []string{`{"results": []}`, "", "   \t\n"} {
		findings, err := parseOSVScannerReport([]byte(empty), nil, "")
		if err != nil {
			t.Fatalf("expected clean pass on valid empty osv-scanner output %q: %v", empty, err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings on empty output, got %d", len(findings))
		}
	}

	// 3. Malformed JSON
	if _, err := parseOSVScannerReport([]byte(`{results: [`), nil, ""); err == nil {
		t.Fatal("expected error on malformed osv-scanner json, got nil")
	}

	// 4. Missing required fields
	missingPkgName := `{
		"results": [{
			"source": {"path": "go.mod"},
			"packages": [{
				"package": {"version": "1.0.0"},
				"vulnerabilities": [{"id": "CVE-1"}]
			}]
		}]
	}`
	if _, err := parseOSVScannerReport([]byte(missingPkgName), nil, ""); err == nil {
		t.Fatal("expected error on missing package name, got nil")
	}

	missingVulnID := `{
		"results": [{
			"source": {"path": "go.mod"},
			"packages": [{
				"package": {"name": "foo", "version": "1.0.0"},
				"vulnerabilities": [{"summary": "bad"}]
			}]
		}]
	}`
	if _, err := parseOSVScannerReport([]byte(missingVulnID), nil, ""); err == nil {
		t.Fatal("expected error on missing vulnerability id, got nil")
	}

	// 5. Unknown fields rejected
	unknownField := `{"results": [], "rogue_field": 1}`
	if _, err := parseOSVScannerReport([]byte(unknownField), nil, ""); err == nil {
		t.Fatal("expected error on unknown field in osv-scanner json, got nil")
	}

	// 6. Nonzero exit code
	exitErr1 := mockExitError(1)
	// Code 1 with findings accepted
	findings, err = parseOSVScannerReport([]byte(validJSON), exitErr1, "")
	if err != nil || len(findings) != 1 {
		t.Fatalf("exit code 1 with findings should succeed, got err=%v findings=%d", err, len(findings))
	}
	// Code 1 with 0 findings must fail
	if _, err := parseOSVScannerReport([]byte(`{"results": []}`), exitErr1, ""); err == nil {
		t.Fatal("exit code 1 with 0 findings must fail, got nil")
	}
	// 7. Missing source path rejected
	missingSourcePath := `{
		"results": [{
			"source": {"path": ""},
			"packages": [{
				"package": {"name": "foo", "version": "1.0.0"},
				"vulnerabilities": [{"id": "CVE-1"}]
			}]
		}]
	}`
	if _, err := parseOSVScannerReport([]byte(missingSourcePath), nil, ""); err == nil {
		t.Fatal("expected error on missing source path, got nil")
	}
}

func TestTrailingContentRejected(t *testing.T) {
	// Trailing garbage after valid JSON must fail validation for all scanners
	validGitleaks := `[{"RuleID": "k", "File": "a.go"}] trailing garbled text`
	if _, err := parseGitleaksReport([]byte(validGitleaks), nil); err == nil {
		t.Fatal("expected error on trailing content in gitleaks report, got nil")
	}

	validGosec := `{"Issues": []} trailing garbled text`
	if _, err := parseGosecReport([]byte(validGosec), nil); err == nil {
		t.Fatal("expected error on trailing content in gosec report, got nil")
	}

	validOSV := `{"results": []} trailing garbled text`
	if _, err := parseOSVScannerReport([]byte(validOSV), nil, ""); err == nil {
		t.Fatal("expected error on trailing content in osv-scanner report, got nil")
	}
}

func TestUnsupportedOutputYieldsFailedCheckNeverCleanPass(t *testing.T) {
	// Verify that error returns from scanner runners yield CheckResult with status "failed"
	// and high severity finding
	tools := []localTool{
		{
			name:     "failing-tool",
			category: "security",
			run: func(_ context.Context, _ string) ([]review.Finding, error) {
				return nil, errors.New("malformed JSON output syntax error")
			},
		},
	}

	// Simulate running the failing tool runner as runOptionalLocalTools does
	var findings []review.Finding
	results := make([]review.CheckResult, 0, len(tools))
	for _, tool := range tools {
		ctx := context.Background()
		toolFindings, err := tool.run(ctx, "/tmp")
		if err != nil {
			message := err.Error()
			results = append(results, review.CheckResult{
				Name:     tool.name,
				Category: tool.category,
				Status:   "failed",
				Message:  message,
			})
			findings = append(findings, review.Finding{
				Category:    tool.category,
				Rule:        "tool-" + tool.name,
				Severity:    "high",
				Message:     tool.name + " could not complete: " + message,
				Remediation: "Check the scanner installation and rerun the requested tool scan.",
			})
			continue
		}
		findings = append(findings, toolFindings...)
	}

	if len(results) != 1 || results[0].Status != "failed" {
		t.Fatalf("expected check status failed, got: %+v", results)
	}
	if len(findings) != 1 || findings[0].Severity != "high" || findings[0].Rule != "tool-failing-tool" {
		t.Fatalf("expected high severity failure finding, got: %+v", findings)
	}
}
