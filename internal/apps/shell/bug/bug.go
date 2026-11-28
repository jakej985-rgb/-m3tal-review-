package bug

import (
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var reCD = regexp.MustCompile(`^\s*cd\s+\S+`)

// Rules returns all Shell bug detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "shell/bug/cd-without-exit", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Summary: "cd without error handling can execute subsequent commands in wrong directory"},
	}
}

// Analyze runs Shell bug detectors.
func Analyze(filePath string, lines []string, allowed func(int) bool, isWorkflow bool) []protocol.Finding {
	if isWorkflow {
		return nil
	}
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
		if reCD.MatchString(raw) && !strings.Contains(raw, "||") && !strings.Contains(raw, "&&") {
			out = append(out, protocol.Finding{
				Rule: "shell/bug/cd-without-exit", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "cd without '|| exit' or '&&' can run later commands in the wrong directory",
				Evidence: trimmed, Remediation: "Use 'cd <dir> || exit 1' or a subshell.",
			})
		}
	}
	return out
}
