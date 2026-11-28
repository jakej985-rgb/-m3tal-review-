package bug

import (
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var reEmptyCatch = regexp.MustCompile(`\bcatch\s*\([^)]*\)\s*\{\s*\}`)

// Rules returns all C/C++ bug detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "cpp/bug/empty-catch", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Summary: "Empty catch block silently swallows C++ exceptions"},
	}
}

// Analyze runs C/C++ bug detectors.
func Analyze(filePath string, lines []string, allowed func(int) bool) []protocol.Finding {
	var out []protocol.Finding
	for i, raw := range lines {
		lineNum := i + 1
		if !allowed(lineNum) {
			continue
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if reEmptyCatch.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "cpp/bug/empty-catch", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Empty catch block silently swallows exceptions",
				Evidence: trimmed, Remediation: "Log, handle, or rethrow the exception.",
			})
		}
	}
	return out
}
