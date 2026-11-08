package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

type localTool struct {
	name     string
	category string
	run      func(context.Context, string) ([]review.Finding, error)
}

func runOptionalLocalTools(repositoryRoot string) ([]review.Finding, []review.CheckResult) {
	tools := []localTool{
		{name: "gitleaks", category: "security", run: runGitleaks},
		{name: "gosec", category: "security", run: runGosec},
		{name: "osv-scanner", category: "security", run: runOSVScanner},
	}
	var findings []review.Finding
	results := make([]review.CheckResult, 0, len(tools))
	for _, tool := range tools {
		if _, err := exec.LookPath(tool.name); err != nil {
			results = append(results, review.CheckResult{Name: tool.name, Category: tool.category, Status: "unavailable", Message: "executable not found on PATH"})
			findings = append(findings, review.Finding{Category: "confidence", Rule: "tool-" + tool.name, Severity: "high", Message: tool.name + " is unavailable; the requested scanner did not run", Remediation: "Install the scanner or rerun without --with-tools."})
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		toolFindings, err := tool.run(ctx, repositoryRoot)
		timedOut := ctx.Err() == context.DeadlineExceeded
		cancel()
		if err != nil {
			message := err.Error()
			if timedOut {
				message = "command exceeded the 5 minute time limit"
			}
			results = append(results, review.CheckResult{Name: tool.name, Category: tool.category, Status: "failed", Message: message})
			findings = append(findings, review.Finding{Category: tool.category, Rule: "tool-" + tool.name, Severity: "high", Message: tool.name + " could not complete: " + message, Remediation: "Check the scanner installation and rerun the requested tool scan."})
			continue
		}
		findings = append(findings, toolFindings...)
		status := "passed"
		message := ""
		if len(toolFindings) > 0 {
			status = "findings"
			message = fmt.Sprintf("%d finding(s)", len(toolFindings))
		}
		results = append(results, review.CheckResult{Name: tool.name, Category: tool.category, Status: status, Message: message})
	}
	return findings, results
}

// --- Gitleaks Schema & Parsing ---

type gitleaksRecord struct {
	RuleID      string   `json:"RuleID"`
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
	File        string   `json:"File"`
	SymlinkFile string   `json:"SymlinkFile"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy"`
	Author      string   `json:"Author"`
	Email       string   `json:"Email"`
	Date        string   `json:"Date"`
	Message     string   `json:"Message"`
	Tags        []string `json:"Tags"`
	Fingerprint string   `json:"Fingerprint"`
}

func parseGitleaksReport(data []byte, runErr error) ([]review.Finding, error) {
	trimmed := strings.TrimSpace(string(data))
	code := commandExitCode(runErr)

	if trimmed == "" {
		if runErr != nil {
			return nil, fmt.Errorf("scanner command failed with code %d: %w", code, runErr)
		}
		return nil, nil // Valid empty output
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var records []gitleaksRecord
	if err := dec.Decode(&records); err != nil {
		return nil, toolCommandError(runErr, fmt.Errorf("decode gitleaks report: %w", err))
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, toolCommandError(runErr, fmt.Errorf("unexpected trailing content in gitleaks report"))
	}

	// Validate required fields
	for i, record := range records {
		if strings.TrimSpace(record.RuleID) == "" {
			return nil, fmt.Errorf("gitleaks record %d missing required field: RuleID", i)
		}
		if strings.TrimSpace(record.File) == "" {
			return nil, fmt.Errorf("gitleaks record %d missing required field: File", i)
		}
	}

	// Nonzero exit code verification:
	// Gitleaks returns exit code 1 when leaks are found.
	// Any exit code > 1 or code 1 with 0 findings is a failure.
	if runErr != nil {
		if code > 1 || (code == 1 && len(records) == 0) {
			return nil, fmt.Errorf("scanner command failed with code %d: %w", code, runErr)
		}
	}

	findings := make([]review.Finding, 0, len(records))
	for _, record := range records {
		message := "Possible secret detected"
		if record.Description != "" {
			message = "Possible secret detected: " + record.Description
		}
		ruleName := "gitleaks-" + record.RuleID
		findings = append(findings, review.Finding{
			Category:    "security",
			Rule:        ruleName,
			Rules:       []string{ruleName},
			Analyzers:   []string{"gitleaks"},
			Severity:    "high",
			RawSeverity: "HIGH",
			Confidence:  "high",
			File:        filepath.ToSlash(record.File),
			Line:        record.StartLine,
			Message:     message,
			Remediation: "Remove the secret and rotate it if it may have been exposed.",
		})
	}
	return findings, nil
}

func runGitleaks(ctx context.Context, repositoryRoot string) ([]review.Finding, error) {
	reportPath, cleanup, err := tempToolReport("gitleaks-*.json")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	_, runErr := runCommand(ctx, repositoryRoot, "gitleaks", "dir", "--no-banner", "--redact=100", "--report-format", "json", "--report-path", reportPath, ".")
	data, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		return nil, toolCommandError(runErr, readErr)
	}
	return parseGitleaksReport(data, runErr)
}

// --- Gosec Schema & Parsing ---

type gosecReport struct {
	Issues       []gosecIssue    `json:"Issues"`
	Stats        *gosecStats     `json:"Stats,omitempty"`
	Errors       json.RawMessage `json:"Errors,omitempty"`
	GolangErrors json.RawMessage `json:"GolangErrors,omitempty"`
	GosecVersion string          `json:"GosecVersion,omitempty"`
}

type gosecIssue struct {
	Severity   string    `json:"severity"`
	Confidence string    `json:"confidence"`
	Cwe        *gosecCwe `json:"cwe,omitempty"`
	RuleID     string    `json:"rule_id"`
	Details    string    `json:"details"`
	File       string    `json:"file"`
	Code       string    `json:"code,omitempty"`
	Line       string    `json:"line"`
	Col        string    `json:"col,omitempty"`
}

type gosecCwe struct {
	ID  string `json:"id"`
	URL string `json:"url,omitempty"`
}

type gosecStats struct {
	Files int `json:"files,omitempty"`
	Lines int `json:"lines,omitempty"`
	Nosec int `json:"nosec,omitempty"`
	Found int `json:"found,omitempty"`
}

func parseGosecReport(data []byte, runErr error) ([]review.Finding, error) {
	trimmed := strings.TrimSpace(string(data))
	code := commandExitCode(runErr)

	if trimmed == "" {
		if runErr != nil {
			return nil, fmt.Errorf("scanner command failed with code %d: %w", code, runErr)
		}
		return nil, nil // Valid empty output
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var report gosecReport
	if err := dec.Decode(&report); err != nil {
		return nil, toolCommandError(runErr, fmt.Errorf("decode gosec report: %w", err))
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, toolCommandError(runErr, fmt.Errorf("unexpected trailing content in gosec report"))
	}

	// Gosec returns exit code 1 when issues are found.
	// Any exit code > 1, code 1 with 0 findings, or negative code is a failure.
	if runErr != nil {
		if code > 1 || (code == 1 && len(report.Issues) == 0) || (code < 0 && len(report.Issues) == 0) {
			return nil, fmt.Errorf("scanner command failed with code %d: %w", code, runErr)
		}
	}

	findings := make([]review.Finding, 0, len(report.Issues))
	for i, issue := range report.Issues {
		if strings.TrimSpace(issue.RuleID) == "" {
			return nil, fmt.Errorf("gosec issue %d missing required field: rule_id", i)
		}
		if strings.TrimSpace(issue.File) == "" {
			return nil, fmt.Errorf("gosec issue %d missing required field: file", i)
		}
		if strings.TrimSpace(issue.Details) == "" {
			return nil, fmt.Errorf("gosec issue %d missing required field: details", i)
		}

		line := parseToolLine(issue.Line)
		normSev, rawSev := review.NormalizeSeverity(issue.Severity)
		normConf, _ := review.NormalizeConfidence(issue.Confidence)

		ruleName := "gosec-" + issue.RuleID
		var advisoryIDs []string
		var advisoryID string
		if issue.Cwe != nil && strings.TrimSpace(issue.Cwe.ID) != "" {
			cwe := strings.TrimSpace(issue.Cwe.ID)
			if !strings.HasPrefix(strings.ToUpper(cwe), "CWE-") {
				cwe = "CWE-" + cwe
			}
			advisoryID = cwe
			advisoryIDs = []string{cwe}
		}

		findings = append(findings, review.Finding{
			Category:    "security",
			Rule:        ruleName,
			Rules:       []string{ruleName},
			Analyzers:   []string{"gosec"},
			Severity:    normSev,
			RawSeverity: rawSev,
			Confidence:  normConf,
			AdvisoryID:  advisoryID,
			AdvisoryIDs: advisoryIDs,
			File:        filepath.ToSlash(issue.File),
			Line:        line,
			Message:     issue.Details,
			Remediation: "Review the gosec rule guidance and correct or document the flagged code.",
		})
	}
	return findings, nil
}

func runGosec(ctx context.Context, repositoryRoot string) ([]review.Finding, error) {
	reportPath, cleanup, err := tempToolReport("gosec-*.json")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	_, runErr := runCommand(ctx, repositoryRoot, "gosec", "-fmt=json", "-out="+reportPath, "./...")
	data, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		return nil, toolCommandError(runErr, readErr)
	}
	return parseGosecReport(data, runErr)
}

// --- OSV-Scanner Schema & Parsing ---

type osvScannerReport struct {
	Results              []osvScannerResult `json:"results"`
	ExperimentalAnalysis any                `json:"experimental_analysis,omitempty"`
}

type osvScannerResult struct {
	Source   osvScannerSource    `json:"source"`
	Packages []osvScannerPackage `json:"packages"`
}

type osvScannerSource struct {
	Path string `json:"path"`
	Type string `json:"type,omitempty"`
}

type osvScannerPackage struct {
	Package         osvScannerPackageInfo `json:"package"`
	Vulnerabilities []osvVulnerability    `json:"vulnerabilities"`
	Groups          []any                 `json:"groups,omitempty"`
}

type osvScannerPackageInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Commit    string `json:"commit,omitempty"`
}

type osvVulnerability struct {
	ID               string           `json:"id"`
	Summary          string           `json:"summary,omitempty"`
	Details          string           `json:"details,omitempty"`
	Aliases          []string         `json:"aliases,omitempty"`
	Modified         string           `json:"modified,omitempty"`
	Published        string           `json:"published,omitempty"`
	DatabaseSpecific any              `json:"database_specific,omitempty"`
	Severity         []osvSeverityObj `json:"severity,omitempty"`
}

type osvSeverityObj struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

func parseOSVScannerReport(data []byte, runErr error, repositoryRoot string) ([]review.Finding, error) {
	trimmed := strings.TrimSpace(string(data))
	code := commandExitCode(runErr)

	if trimmed == "" {
		if runErr != nil {
			return nil, fmt.Errorf("scanner command failed with code %d: %w", code, runErr)
		}
		return nil, nil // Valid empty output
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var report osvScannerReport
	if err := dec.Decode(&report); err != nil {
		return nil, fmt.Errorf("decode osv-scanner report: %w", err)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("unexpected trailing content in osv-scanner report")
	}

	findings := make([]review.Finding, 0)
	for i, result := range report.Results {
		if strings.TrimSpace(result.Source.Path) == "" {
			return nil, fmt.Errorf("osv-scanner result %d missing required field: path", i)
		}
		file := result.Source.Path
		if repositoryRoot != "" && filepath.IsAbs(file) {
			if relative, err := filepath.Rel(repositoryRoot, file); err == nil && filepath.IsLocal(relative) {
				file = relative
			}
		}
		for j, pkg := range result.Packages {
			if strings.TrimSpace(pkg.Package.Name) == "" {
				return nil, fmt.Errorf("osv-scanner result %d pkg %d missing required field: name", i, j)
			}
			for k, vulnerability := range pkg.Vulnerabilities {
				if strings.TrimSpace(vulnerability.ID) == "" {
					return nil, fmt.Errorf("osv-scanner result %d pkg %d vuln %d missing required field: id", i, j, k)
				}

				// Compute severity and preserve raw
				normSev, rawSev := parseOSVSeverity(vulnerability.Severity)

				// Collect all advisory IDs (canonical ID + aliases)
				advisoryIDs := make([]string, 0, 1+len(vulnerability.Aliases))
				advisoryIDs = append(advisoryIDs, vulnerability.ID)
				for _, a := range vulnerability.Aliases {
					if a != "" && a != vulnerability.ID {
						advisoryIDs = append(advisoryIDs, a)
					}
				}

				message := fmt.Sprintf("Known vulnerable dependency %s@%s: %s", pkg.Package.Name, pkg.Package.Version, vulnerability.ID)
				if vulnerability.Summary != "" {
					message += " — " + vulnerability.Summary
				}
				ruleName := "osv-" + vulnerability.ID
				findings = append(findings, review.Finding{
					Category:    "security",
					Rule:        ruleName,
					Rules:       []string{ruleName},
					Analyzers:   []string{"osv-scanner"},
					Severity:    normSev,
					RawSeverity: rawSev,
					Confidence:  "high",
					AdvisoryID:  vulnerability.ID,
					AdvisoryIDs: advisoryIDs,
					File:        filepath.ToSlash(file),
					Message:     message,
					Remediation: "Update the dependency to a version without this advisory, or record an approved exception.",
				})
			}
		}
	}

	// Exit code check:
	// osv-scanner exits 1 (or findings exit code) when vulnerabilities are found.
	// If exit code is nonzero and no findings were parsed, or code > 1, it's a failure.
	if runErr != nil {
		if code > 1 || (code == 1 && len(findings) == 0) || (code < 0 && len(findings) == 0) {
			return nil, fmt.Errorf("run osv-scanner failed with code %d: %w", code, runErr)
		}
	}

	return findings, nil
}

func parseOSVSeverity(severities []osvSeverityObj) (normalized string, raw string) {
	for _, s := range severities {
		if s.Score != "" {
			raw = s.Score
			norm, _ := review.NormalizeSeverity(s.Score)
			if norm != "" && norm != "info" {
				return norm, raw
			}
		}
	}
	if len(severities) > 0 && severities[0].Score != "" {
		norm, rawSev := review.NormalizeSeverity(severities[0].Score)
		return norm, rawSev
	}
	return "high", raw
}

func runOSVScanner(ctx context.Context, repositoryRoot string) ([]review.Finding, error) {
	output, runErr := runCommandOutput(ctx, repositoryRoot, "osv-scanner", "scan", "source", "--recursive", "--format", "json", ".")
	return parseOSVScannerReport(output, runErr, repositoryRoot)
}

func tempToolReport(pattern string) (string, func(), error) {
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", func() {}, fmt.Errorf("create temporary scanner report: %w", err)
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return "", func() {}, fmt.Errorf("close temporary scanner report: %w", err)
	}
	return name, func() { _ = os.Remove(name) }, nil
}

func toolCommandError(runErr error, reportErr error) error {
	if runErr != nil {
		return fmt.Errorf("scanner command failed: %w", runErr)
	}
	return reportErr
}

func commandExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func parseToolLine(value string) int {
	first := strings.FieldsFunc(value, func(r rune) bool {
		return r == ':' || r == '-' || r == ','
	})
	if len(first) > 0 {
		line, _ := strconv.Atoi(first[0])
		return line
	}
	return 0
}
