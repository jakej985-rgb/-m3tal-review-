package bug

import (
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var (
	reEmptyCatch     = regexp.MustCompile(`catch\s*(\([^)]*\))?\s*\{\s*\}`)
	reMissingRadix   = regexp.MustCompile(`\bparseInt\s*\(\s*[^,)]+\s*\)`)
	reLooseEq        = regexp.MustCompile(`[^=!]==[^=]`)
	reLooseEqNullish = regexp.MustCompile(`==\s*(null|undefined)\b`)
)

// Rules returns all TS/JS bug detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "ts/bug/empty-catch", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Summary: "Empty catch block silently swallows errors"},
		{ID: "ts/bug/missing-radix", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Summary: "parseInt() called without explicit radix"},
		{ID: "ts/bug/non-strict-equality", Category: protocol.CategoryBug, Severity: protocol.SeverityLow, Summary: "Loose == / != comparison (use === / !==)"},
	}
}

// Analyze runs TS/JS bug detectors over masked and raw lines.
func Analyze(filePath string, maskedLines, rawLines []string, allowed func(int) bool) []protocol.Finding {
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
		if reEmptyCatch.MatchString(trimmed) {
			out = append(out, protocol.Finding{
				Rule: "ts/bug/empty-catch", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Empty catch block silently swallows errors",
				Evidence: rawTrimmed, Remediation: "Log, handle, or rethrow the caught error.",
			})
		}
		if reMissingRadix.MatchString(trimmed) {
			out = append(out, protocol.Finding{
				Rule: "ts/bug/missing-radix", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "parseInt() called without explicit radix (e.g. 10)",
				Evidence: rawTrimmed, Remediation: "Pass an explicit radix: parseInt(str, 10).",
			})
		}
		if reLooseEq.MatchString(trimmed) && !reLooseEqNullish.MatchString(trimmed) {
			out = append(out, protocol.Finding{
				Rule: "ts/bug/non-strict-equality", Category: protocol.CategoryBug, Severity: protocol.SeverityLow, Confidence: protocol.ConfidenceMedium,
				File: filePath, Line: lineNum, Message: "Loose == comparison can coerce types unexpectedly",
				Evidence: rawTrimmed, Remediation: "Use strict === comparison.",
			})
		}
	}
	return out
}
