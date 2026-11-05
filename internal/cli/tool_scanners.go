package cli

import (
	"context"
	"encoding/json"
	"fmt"
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
	var records []struct {
		RuleID      string `json:"RuleID"`
		Description string `json:"Description"`
		File        string `json:"File"`
		StartLine   int    `json:"StartLine"`
	}
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, toolCommandError(runErr, fmt.Errorf("decode gitleaks report: %w", err))
	}
	findings := make([]review.Finding, 0, len(records))
	for _, record := range records {
		message := "Possible secret detected"
		if record.Description != "" {
			message = "Possible secret detected: " + record.Description
		}
		findings = append(findings, review.Finding{Category: "security", Rule: "gitleaks-" + record.RuleID, Severity: "high", File: filepath.ToSlash(record.File), Line: record.StartLine, Message: message, Remediation: "Remove the secret and rotate it if it may have been exposed."})
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
	var report struct {
		Issues []struct {
			Severity string `json:"severity"`
			RuleID   string `json:"rule_id"`
			Details  string `json:"details"`
			File     string `json:"file"`
			Line     string `json:"line"`
		} `json:"Issues"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, toolCommandError(runErr, fmt.Errorf("decode gosec report: %w", err))
	}
	findings := make([]review.Finding, 0, len(report.Issues))
	for _, issue := range report.Issues {
		line := parseToolLine(issue.Line)
		severity := "medium"
		if strings.EqualFold(issue.Severity, "HIGH") {
			severity = "high"
		}
		findings = append(findings, review.Finding{Category: "security", Rule: "gosec-" + issue.RuleID, Severity: severity, File: filepath.ToSlash(issue.File), Line: line, Message: issue.Details, Remediation: "Review the gosec rule guidance and correct or document the flagged code."})
	}
	return findings, nil
}

func runOSVScanner(ctx context.Context, repositoryRoot string) ([]review.Finding, error) {
	output, runErr := runCommandOutput(ctx, repositoryRoot, "osv-scanner", "scan", "source", "--recursive", "--format", "json", ".")
	if runErr != nil && len(output) == 0 {
		return nil, fmt.Errorf("run osv-scanner: %w", runErr)
	}
	var report struct {
		Results []struct {
			Source struct {
				Path string `json:"path"`
			} `json:"source"`
			Packages []struct {
				Package struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID      string `json:"id"`
					Summary string `json:"summary"`
				} `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("decode osv-scanner report: %w", err)
	}
	findings := make([]review.Finding, 0)
	for _, result := range report.Results {
		file := result.Source.Path
		if filepath.IsAbs(file) {
			if relative, err := filepath.Rel(repositoryRoot, file); err == nil && filepath.IsLocal(relative) {
				file = relative
			}
		}
		for _, pkg := range result.Packages {
			for _, vulnerability := range pkg.Vulnerabilities {
				message := fmt.Sprintf("Known vulnerable dependency %s@%s: %s", pkg.Package.Name, pkg.Package.Version, vulnerability.ID)
				if vulnerability.Summary != "" {
					message += " — " + vulnerability.Summary
				}
				findings = append(findings, review.Finding{Category: "security", Rule: "osv-" + vulnerability.ID, Severity: "high", File: filepath.ToSlash(file), Message: message, Remediation: "Update the dependency to a version without this advisory, or record an approved exception."})
			}
		}
	}
	if runErr != nil && len(findings) == 0 {
		return nil, fmt.Errorf("run osv-scanner: %w", runErr)
	}
	return findings, nil
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

func parseToolLine(value string) int {
	line, _ := strconv.Atoi(strings.SplitN(value, ":", 2)[0])
	return line
}
