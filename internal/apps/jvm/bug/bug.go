package bug

import (
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var reGlobalScope = regexp.MustCompile(`\bGlobalScope\s*\.\s*(launch|async)\b`)

// Rules returns all JVM bug detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "jvm/bug/coroutine-global-scope", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Summary: "GlobalScope.launch/async leaks coroutines beyond structured concurrency"},
	}
}

// Analyze runs JVM bug detectors.
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
		if reGlobalScope.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "jvm/bug/coroutine-global-scope", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "GlobalScope.launch/async bypasses structured concurrency",
				Evidence: trimmed, Remediation: "Use a lifecycle-bound CoroutineScope (viewModelScope, lifecycleScope, or injected scope).",
			})
		}
	}
	return out
}
