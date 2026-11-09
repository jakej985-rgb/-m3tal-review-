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
	"regexp"
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

type localToolSpec struct {
	name        string
	category    string
	minVersion  string
	versionArgs []string
	runExec     func(ctx context.Context, execPath, repositoryRoot string) ([]review.Finding, error)
}

func runOptionalLocalTools(repositoryRoot string) ([]review.Finding, []review.CheckResult) {
	return runOptionalLocalToolsWithOverrides(repositoryRoot, nil)
}

func runOptionalLocalToolsWithOverrides(repositoryRoot string, overrides map[string]string) ([]review.Finding, []review.CheckResult) {
	toolSpecs := []localToolSpec{
		{name: "gitleaks", category: "security", minVersion: "8.0.0", versionArgs: []string{"version"}, runExec: runGitleaksExec},
		{name: "gosec", category: "security", minVersion: "2.0.0", versionArgs: []string{"-version"}, runExec: runGosecExec},
		{name: "osv-scanner", category: "security", minVersion: "1.0.0", versionArgs: []string{"--version"}, runExec: runOSVScannerExec},
	}

	var findings []review.Finding
	results := make([]review.CheckResult, 0, len(toolSpecs))

	for _, tool := range toolSpecs {
		resolvedPath, isExplicit, err := resolveToolExecutable(tool.name, overrides)
		if err != nil {
			status := "unavailable"
			msg := "executable not found on PATH"
			if isExplicit {
				status = "failed"
				msg = fmt.Sprintf("invalid executable override for %s: %s", tool.name, displayText(err.Error()))
			}
			results = append(results, review.CheckResult{
				Name:     tool.name,
				Category: tool.category,
				Status:   status,
				Message:  msg,
				Path:     resolvedPath,
			})
			findings = append(findings, review.Finding{
				Category:    "confidence",
				Rule:        "tool-" + tool.name,
				Severity:    "high",
				Message:     fmt.Sprintf("%s is unavailable: %s", displayText(tool.name), msg),
				Remediation: "Install the scanner or check the configured executable path.",
			})
			continue
		}

		// Enforce version compatibility
		version, err := getToolVersion(context.Background(), resolvedPath, tool.versionArgs)
		if err != nil {
			msg := fmt.Sprintf("failed to determine %s version: %s (requires >= %s)", displayText(tool.name), displayText(err.Error()), tool.minVersion)
			results = append(results, review.CheckResult{
				Name:     tool.name,
				Category: tool.category,
				Status:   "unavailable",
				Message:  msg,
				Path:     resolvedPath,
			})
			findings = append(findings, review.Finding{
				Category:    "confidence",
				Rule:        "tool-" + tool.name,
				Severity:    "high",
				Message:     msg + "; scanner did not run",
				Remediation: fmt.Sprintf("Ensure %s is functional and meets version requirement >= %s.", displayText(tool.name), tool.minVersion),
			})
			continue
		}

		compat, err := checkVersionCompatibility(version, tool.minVersion)
		if err != nil || !compat {
			msg := fmt.Sprintf("incompatible version %s (requires >= %s)", displayText(version), tool.minVersion)
			results = append(results, review.CheckResult{
				Name:     tool.name,
				Category: tool.category,
				Status:   "unavailable",
				Message:  msg,
				Version:  version,
				Path:     resolvedPath,
			})
			findings = append(findings, review.Finding{
				Category:    "confidence",
				Rule:        "tool-" + tool.name,
				Severity:    "high",
				Message:     fmt.Sprintf("%s version %s is incompatible (requires >= %s); scanner did not run", displayText(tool.name), displayText(version), tool.minVersion),
				Remediation: fmt.Sprintf("Upgrade %s to version >= %s or rerun without --with-tools.", displayText(tool.name), tool.minVersion),
			})
			continue
		}

		// Compatible version resolved
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		toolFindings, err := tool.runExec(ctx, resolvedPath, repositoryRoot)
		timedOut := ctx.Err() == context.DeadlineExceeded
		cancel()
		if err != nil {
			message := err.Error()
			if timedOut {
				message = "command exceeded the 5 minute time limit"
			}
			results = append(results, review.CheckResult{
				Name:     tool.name,
				Category: tool.category,
				Status:   "failed",
				Message:  message,
				Version:  version,
				Path:     resolvedPath,
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
		status := "passed"
		message := ""
		if len(toolFindings) > 0 {
			status = "findings"
			message = fmt.Sprintf("%d finding(s)", len(toolFindings))
		}
		results = append(results, review.CheckResult{
			Name:     tool.name,
			Category: tool.category,
			Status:   status,
			Message:  message,
			Version:  version,
			Path:     resolvedPath,
		})
	}
	return findings, results
}

func resolveToolExecutable(toolName string, overrides map[string]string) (string, bool, error) {
	// 1. Explicit overrides map
	if overrides != nil {
		if path, ok := overrides[toolName]; ok && strings.TrimSpace(path) != "" {
			trimmed := strings.TrimSpace(path)
			if err := validateExecutablePath(trimmed); err != nil {
				return trimmed, true, err
			}
			return trimmed, true, nil
		}
	}

	// 2. Specific environment variables
	envKey := "M3TAL_" + strings.ToUpper(strings.ReplaceAll(toolName, "-", "_")) + "_PATH"
	if envPath := strings.TrimSpace(os.Getenv(envKey)); envPath != "" {
		if err := validateExecutablePath(envPath); err != nil {
			return envPath, true, err
		}
		return envPath, true, nil
	}
	genericEnv := "M3TAL_TOOL_PATH_" + strings.ToUpper(strings.ReplaceAll(toolName, "-", "_"))
	if envPath := strings.TrimSpace(os.Getenv(genericEnv)); envPath != "" {
		if err := validateExecutablePath(envPath); err != nil {
			return envPath, true, err
		}
		return envPath, true, nil
	}

	// 3. System PATH lookup
	found, err := exec.LookPath(toolName)
	if err != nil {
		return "", false, err
	}
	if err := validateExecutablePath(found); err != nil {
		return found, false, err
	}
	return found, false, nil
}

func validateExecutablePath(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("file not found: %w", err)
	}
	if fi.IsDir() {
		return errors.New("path is a directory")
	}
	if fi.Mode()&0111 == 0 {
		return errors.New("file is not executable")
	}
	return nil
}

var semverRegex = regexp.MustCompile(`(?i)\bv?(\d+)\.(\d+)(?:\.(\d+))?`)

func parseSemver(output string) (string, int, int, int, error) {
	matches := semverRegex.FindStringSubmatch(output)
	if len(matches) < 3 {
		return "", 0, 0, 0, fmt.Errorf("no semver found in output: %s", displayText(strings.TrimSpace(output)))
	}
	major, err1 := strconv.Atoi(matches[1])
	minor, err2 := strconv.Atoi(matches[2])
	patch := 0
	if len(matches) > 3 && matches[3] != "" {
		patch, _ = strconv.Atoi(matches[3])
	}
	if err1 != nil || err2 != nil {
		return "", 0, 0, 0, fmt.Errorf("invalid semver digits: %s", matches[0])
	}
	return fmt.Sprintf("%d.%d.%d", major, minor, patch), major, minor, patch, nil
}

func checkVersionCompatibility(actual, minRequired string) (bool, error) {
	_, aMaj, aMin, aPatch, err := parseSemver(actual)
	if err != nil {
		return false, err
	}
	_, rMaj, rMin, rPatch, err := parseSemver(minRequired)
	if err != nil {
		return false, err
	}
	if aMaj != rMaj {
		return aMaj > rMaj, nil
	}
	if aMin != rMin {
		return aMin > rMin, nil
	}
	return aPatch >= rPatch, nil
}

func getToolVersion(ctx context.Context, execPath string, args []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, execPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", fmt.Errorf("failed to run %s %v: %w", execPath, args, err)
	}
	vStr, _, _, _, err := parseSemver(string(out))
	if err != nil {
		return "", fmt.Errorf("could not parse version from output: %w", err)
	}
	return vStr, nil
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
	return runGitleaksExec(ctx, "gitleaks", repositoryRoot)
}

func runGitleaksExec(ctx context.Context, execPath, repositoryRoot string) ([]review.Finding, error) {
	reportPath, cleanup, err := tempToolReport("gitleaks-*.json")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	_, runErr := runCommand(ctx, repositoryRoot, execPath, "dir", "--no-banner", "--redact=100", "--report-format", "json", "--report-path", reportPath, ".")
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
	return runGosecExec(ctx, "gosec", repositoryRoot)
}

func runGosecExec(ctx context.Context, execPath, repositoryRoot string) ([]review.Finding, error) {
	reportPath, cleanup, err := tempToolReport("gosec-*.json")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	_, runErr := runCommand(ctx, repositoryRoot, execPath, "-fmt=json", "-out="+reportPath, "./...")
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
	return runOSVScannerExec(ctx, "osv-scanner", repositoryRoot)
}

func runOSVScannerExec(ctx context.Context, execPath, repositoryRoot string) ([]review.Finding, error) {
	output, runErr := runCommandOutput(ctx, repositoryRoot, execPath, "scan", "source", "--recursive", "--format", "json", ".")
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
