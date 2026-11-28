package slop

import (
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var reBroadAllow = regexp.MustCompile(`#!?\s*\[\s*allow\s*\(\s*(?:warnings|clippy::all)\s*\)\s*\]`)

// Rules returns all Rust slop detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "rust/slop/broad-allow-lint", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Summary: "Broad #[allow(warnings)] or #[allow(clippy::all)] suppresses diagnostics"},
	}
}

// Analyze runs Rust slop detectors.
func Analyze(filePath string, lines []string, allowed func(int) bool) []protocol.Finding {
	var out []protocol.Finding
	for i, raw := range lines {
		lineNum := i + 1
		if !allowed(lineNum) {
			continue
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if reBroadAllow.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "rust/slop/broad-allow-lint", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Broad #[allow(warnings)] / #[allow(clippy::all)] attribute",
				Evidence: trimmed, Remediation: "Allow only the specific lint needed with an explanatory comment.",
			})
		}
	}
	return out
}
