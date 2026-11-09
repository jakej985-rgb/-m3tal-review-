package plugin

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// NormalizePluginFindings cleans and standardizes findings produced by an analyzer plugin.
func NormalizePluginFindings(pluginName string, findings []review.Finding, repoRoot string) []review.Finding {
	if len(findings) == 0 {
		return findings
	}

	normalized := make([]review.Finding, 0, len(findings))
	for _, f := range findings {
		// Category normalization
		cat := strings.ToLower(strings.TrimSpace(f.Category))
		switch cat {
		case "security", "slop", "drift", "confidence", "risk":
			f.Category = cat
		default:
			f.Category = "security"
		}

		// Severity normalization
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		switch sev {
		case "critical", "high", "medium", "low", "info":
			f.Severity = sev
		case "warn", "warning":
			f.Severity = "medium"
		case "err", "error":
			f.Severity = "high"
		default:
			f.Severity = "medium"
		}

		// File path normalization
		filePath := strings.TrimSpace(f.File)
		if repoRoot != "" && filepath.IsAbs(filePath) {
			if rel, err := filepath.Rel(repoRoot, filePath); err == nil && !strings.HasPrefix(rel, "..") {
				filePath = rel
			}
		}
		filePath = filepath.ToSlash(filepath.Clean(filePath))
		filePath = strings.TrimPrefix(filePath, "./")
		filePath = strings.TrimPrefix(filePath, "/")
		f.File = filePath

		// Line bounds
		if f.Line < 0 {
			f.Line = 0
		}

		// Rule normalization
		rule := strings.TrimSpace(f.Rule)
		if rule == "" {
			rule = "plugin-" + pluginName
		}
		f.Rule = rule
		if len(f.Rules) == 0 {
			f.Rules = []string{rule}
		}

		// Analyzers tracking
		hasPlugin := false
		for _, a := range f.Analyzers {
			if a == pluginName {
				hasPlugin = true
				break
			}
		}
		if !hasPlugin {
			f.Analyzers = append(f.Analyzers, pluginName)
		}

		// Message fallback
		if strings.TrimSpace(f.Message) == "" {
			f.Message = fmt.Sprintf("Issue detected by %s plugin", pluginName)
		}

		normalized = append(normalized, f)
	}

	return normalized
}

// NormalizePluginOutput normalizes findings and checks from a plugin execution.
func NormalizePluginOutput(meta PluginMetadata, out PluginOutput, repoRoot string) PluginOutput {
	out.Findings = NormalizePluginFindings(meta.Name, out.Findings, repoRoot)

	// Ensure at least one check result representing plugin health exists
	hasPluginCheck := false
	for _, c := range out.Checks {
		if c.Name == meta.Name {
			hasPluginCheck = true
			break
		}
	}

	if !hasPluginCheck {
		status := "passed"
		msg := "completed successfully"
		if !out.Success || out.Error != "" {
			status = "failed"
			msg = out.Error
			if msg == "" {
				msg = "plugin execution failed"
			}
		} else if len(out.Findings) > 0 {
			status = "findings"
			msg = fmt.Sprintf("%d finding(s) reported", len(out.Findings))
		}

		out.Checks = append(out.Checks, review.CheckResult{
			Name:     meta.Name,
			Category: "plugin",
			Status:   status,
			Message:  msg,
			Version:  meta.Version,
		})
	}

	return out
}
