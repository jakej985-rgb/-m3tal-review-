package bug

import (
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var (
	reBareExcept = regexp.MustCompile(`^\s*except\s*:\s*(#.*)?$`)
	reMutableDef = regexp.MustCompile(`^\s*(?:async\s+)?def\s+\w+\s*\([^)]*=\s*(?:\[\]|\{\}|set\(\)|list\(\)|dict\(\))`)
)

// Rules returns all Python bug detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "py/bug/bare-except", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Summary: "Bare except catches SystemExit and KeyboardInterrupt"},
		{ID: "py/bug/mutable-default-arg", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Summary: "Mutable default argument is shared across calls"},
	}
}

// Analyze runs Python bug detectors.
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
		if reBareExcept.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "py/bug/bare-except", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Bare except: catches BaseException including KeyboardInterrupt",
				Evidence: trimmed, Remediation: "Catch Exception or a specific exception type.",
			})
		}
		if reMutableDef.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "py/bug/mutable-default-arg", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Mutable default argument is shared across function calls",
				Evidence: trimmed, Remediation: "Default to None and initialize inside the function body.",
			})
		}
	}
	return out
}
