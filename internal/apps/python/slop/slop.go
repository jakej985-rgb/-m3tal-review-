package slop

import (
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var (
	reBoolCmp = regexp.MustCompile(`(?:==|!=)\s*(?:True|False)\b`)
	reNoneEq  = regexp.MustCompile(`(?:==|!=)\s*None\b`)
)

// Rules returns all Python slop detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "py/slop/redundant-bool-compare", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Summary: "Redundant comparison to True/False"},
		{ID: "py/slop/none-equality", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Summary: "Use 'is None' / 'is not None' instead of == / !="},
	}
}

// Analyze runs Python slop detectors.
func Analyze(filePath string, lines []string, allowed func(int) bool) []protocol.Finding {
	var out []protocol.Finding
	for i, raw := range lines {
		lineNum := i + 1
		if !allowed(lineNum) {
			continue
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if reBoolCmp.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "py/slop/redundant-bool-compare", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Redundant comparison to True/False",
				Evidence: trimmed, Remediation: "Use the boolean expression directly or 'not expr'.",
			})
		}
		if reNoneEq.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "py/slop/none-equality", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Comparison to None using ==/!= instead of 'is'/'is not'",
				Evidence: trimmed, Remediation: "Use 'is None' or 'is not None'.",
			})
		}
	}
	return out
}
