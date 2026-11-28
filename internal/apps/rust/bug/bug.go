package bug

import (
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var reUnwrap = regexp.MustCompile(`\.unwrap\s*\(\s*\)`)

// Rules returns all Rust bug detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "rust/bug/unwrap-in-prod", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Summary: ".unwrap() in non-test Rust code can panic at runtime"},
	}
}

// Analyze runs Rust bug detectors.
func Analyze(filePath string, lines []string, allowed func(int) bool, isTest bool) []protocol.Finding {
	if isTest {
		return nil
	}
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
		if reUnwrap.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "rust/bug/unwrap-in-prod", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Confidence: protocol.ConfidenceMedium,
				File: filePath, Line: lineNum, Message: ".unwrap() in non-test code can panic at runtime",
				Evidence: trimmed, Remediation: "Propagate the error with ? or handle None/Err explicitly.",
			})
		}
	}
	return out
}
