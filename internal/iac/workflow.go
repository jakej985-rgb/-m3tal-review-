// Package iac analyzes GitHub Actions workflows for supply chain and CI/CD security risks.
package iac

import "regexp"
import "strings"

var (
	echoTokenRe  = regexp.MustCompile(`(?i)\becho\s+.*\$\{\{\s*secrets\.[^}]+\}\}`)
	prHeadRefRe  = regexp.MustCompile(`ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.sha\s*\}\}`)
	writeTokenRe = regexp.MustCompile(`(?i)^\s*permissions:\s*write-all\b`)
)

func evaluateWorkflowStep(col *Collector, file, line, trimmed string, num int, hasPR bool) {
	if writeTokenRe.MatchString(trimmed) {
		col.AddWorkflow(file, "workflow-excessive-permissions", "high",
			"Workflow requests blanket 'write-all' permissions token",
			"Declare fine-grained least-privilege permissions (e.g. contents: read)", num)
	}

	if echoTokenRe.MatchString(line) {
		col.AddWorkflow(file, "workflow-secret-echo", "critical",
			"Shell command echoes secret token directly to console logs",
			"Never echo secrets in shell scripts; pass as environment variables", num)
	}

	if hasPR && prHeadRefRe.MatchString(line) {
		col.AddWorkflow(file, "workflow-unsafe-pr-target", "critical",
			"pull_request_target workflow checks out untrusted pull request code",
			"Do not checkout untrusted PR code in privileged pull_request_target workflows", num)
	}
}

// AnalyzeWorkflow inspects a GitHub Actions workflow YAML file for high-risk configurations.
func AnalyzeWorkflow(filePath, content string) []ConfigFinding {
	var col Collector
	hasPRTarget := false
	hasPermissions := false
	inJobs := false

	workflowLines := strings.Split(content, "\n")
	for i, line := range workflowLines {
		num := i + 1
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, "pull_request_target") {
			hasPRTarget = true
		}
		if !inJobs && strings.HasPrefix(trimmed, "jobs:") {
			inJobs = true
		}
		if !inJobs && strings.HasPrefix(trimmed, "permissions:") {
			hasPermissions = true
		}

		evaluateWorkflowStep(&col, filePath, line, trimmed, num, hasPRTarget)
	}

	if len(workflowLines) > 0 && !hasPermissions {
		col.AddWorkflow(filePath, "workflow-missing-permissions", "medium",
			"Workflow missing top-level explicit permissions declaration",
			"Add 'permissions: read-all' or empty 'permissions: {}' at workflow top-level", 1)
	}

	res := col.Results()
	return res
}
