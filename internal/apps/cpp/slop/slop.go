package slop

import (
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var reUsingNS = regexp.MustCompile(`^\s*using\s+namespace\s+[A-Za-z_][A-Za-z0-9_:]*\s*;`)

// Rules returns all C/C++ slop detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "cpp/slop/using-namespace-header", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Summary: "using namespace directive in header file pollutes includers"},
	}
}

// Analyze runs C/C++ slop detectors.
func Analyze(filePath string, lines []string, allowed func(int) bool, isHeader bool) []protocol.Finding {
	if !isHeader {
		return nil
	}
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
		if reUsingNS.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "cpp/slop/using-namespace-header", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "using namespace in header file pollutes all translation units",
				Evidence: trimmed, Remediation: "Use explicit namespace qualification in header files.",
			})
		}
	}
	return out
}
