package slop

import (
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var reDebug = regexp.MustCompile(`(System\.out\.println\s*\(|\.printStackTrace\s*\(\s*\))`)

// Rules returns all JVM slop detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "jvm/slop/debug-leftover", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Summary: "System.out.println or printStackTrace() debug leftover"},
	}
}

// Analyze runs JVM slop detectors.
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
		if reDebug.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "jvm/slop/debug-leftover", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Debug output leftover (System.out.println / printStackTrace)",
				Evidence: trimmed, Remediation: "Use structured logging or remove debug output.",
			})
		}
	}
	return out
}
