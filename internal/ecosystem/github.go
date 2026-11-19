// Package ecosystem formats GitHub Actions workflow annotations and validates token scopes.
package ecosystem

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

var (
	patTokenRe   = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b`)
	bearerAuthRe = regexp.MustCompile(`(?i)\bbearer\s+[a-zA-Z0-9_\-\.]{16,}\b`)
	ghFinePatRe  = regexp.MustCompile(`\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b`)
)

// EscapeWorkflowProperty escapes parameters for GitHub Actions workflow command properties.
func EscapeWorkflowProperty(val string) string {
	r := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C")
	return r.Replace(val)
}

// EscapeWorkflowData escapes the message payload of a GitHub Actions workflow command.
func EscapeWorkflowData(val string) string {
	r := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	return r.Replace(val)
}

// RedactWorkflowSecrets strips tokens from text before emitting workflow log output.
func RedactWorkflowSecrets(text string) string {
	cleaned := patTokenRe.ReplaceAllString(text, "[REDACTED_GITHUB_TOKEN]")
	cleaned = ghFinePatRe.ReplaceAllString(cleaned, "[REDACTED_FINE_GRAINED_PAT]")
	return bearerAuthRe.ReplaceAllString(cleaned, "Bearer [REDACTED]")
}

// FormatGitHubAnnotation converts a finding to a GitHub Actions command.
func FormatGitHubAnnotation(f model.Finding) string {
	level := "warning"
	switch f.Severity {
	case "critical", "high":
		level = "error"
	case "low", "info":
		level = "notice"
	}

	loc := f.File
	line := f.Line

	var props []string
	if loc != "" {
		props = append(props, fmt.Sprintf("file=%s", EscapeWorkflowProperty(loc)))
	}
	if line > 0 {
		props = append(props, fmt.Sprintf("line=%d", line))
	}
	props = append(props, fmt.Sprintf("title=%s", EscapeWorkflowProperty(f.Rule)))

	safeMsg := RedactWorkflowSecrets(f.Message)
	if safeMsg == "" {
		safeMsg = RedactWorkflowSecrets(f.Rule)
	}

	propStr := strings.Join(props, ",")
	return fmt.Sprintf("::%s %s::%s", level, propStr, EscapeWorkflowData(safeMsg))
}

// ValidateTokenPermissions verifies that token permissions adhere to least privilege.
func ValidateTokenPermissions(perms map[string]string) []string {
	var warnings []string
	if perms["all"] == "write" || perms["write-all"] == "true" {
		warnings = append(warnings, "Workflow requests write-all blanket permissions")
	}
	if perms["administration"] == "write" {
		warnings = append(warnings, "Workflow requests administrative write privileges")
	}
	return warnings
}
