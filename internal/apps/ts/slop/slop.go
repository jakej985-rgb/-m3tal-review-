package slop

import (
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var (
	reExplicitAny   = regexp.MustCompile(`:\s*any\b`)
	reRedundantBool = regexp.MustCompile(`(===|!==)\s*(true|false)\b`)
)

// Rules returns all TS/JS slop detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "ts/slop/explicit-any", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Summary: "Explicit any type annotation weakens type safety"},
		{ID: "ts/slop/redundant-boolean", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Summary: "Redundant === true / === false comparison"},
	}
}

// Analyze runs TS/JS slop detectors over masked and raw lines.
func Analyze(filePath string, isTS bool, maskedLines, rawLines []string, allowed func(int) bool) []protocol.Finding {
	var out []protocol.Finding
	for i, mLine := range maskedLines {
		lineNum := i + 1
		if !allowed(lineNum) {
			continue
		}
		trimmed := strings.TrimSpace(mLine)
		if trimmed == "" {
			continue
		}
		rawTrimmed := strings.TrimSpace(rawLines[i])
		if isTS && reExplicitAny.MatchString(trimmed) {
			out = append(out, protocol.Finding{
				Rule: "ts/slop/explicit-any", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Explicit any annotation bypasses TypeScript type checking",
				Evidence: rawTrimmed, Remediation: "Use unknown, a specific interface, or a generic type parameter.",
			})
		}
		if reRedundantBool.MatchString(trimmed) {
			out = append(out, protocol.Finding{
				Rule: "ts/slop/redundant-boolean", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Redundant strict comparison to boolean literal",
				Evidence: rawTrimmed, Remediation: "Use the boolean expression directly.",
			})
		}
	}
	return out
}
