package security

import (
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var (
	reEval   = regexp.MustCompile(`\beval\s*\(`)
	reExec   = regexp.MustCompile(`\bexec\s*\(`)
	reDOMXSS = regexp.MustCompile(`(\.innerHTML\s*=|\.outerHTML\s*=|dangerouslySetInnerHTML)`)
)

// Rules returns all TS/JS security detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "ts/security/eval-call", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "Dynamic code execution via eval()"},
		{ID: "ts/security/child-process-exec", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "Shell command execution via child_process.exec()"},
		{ID: "ts/security/dom-xss", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "DOM XSS sink (innerHTML/outerHTML/dangerouslySetInnerHTML)"},
	}
}

// Analyze runs TS/JS security detectors over masked and raw lines.
func Analyze(filePath, content string, maskedLines, rawLines []string, allowed func(int) bool) []protocol.Finding {
	var out []protocol.Finding
	hasChildProc := strings.Contains(content, "child_process")
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
		if reEval.MatchString(trimmed) {
			out = append(out, protocol.Finding{
				Rule: "ts/security/eval-call", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "eval() executes arbitrary strings as code",
				Evidence: rawTrimmed, Remediation: "Replace eval() with safe parsing (e.g., JSON.parse) or explicit dispatch.",
			})
		}
		if hasChildProc && reExec.MatchString(trimmed) {
			out = append(out, protocol.Finding{
				Rule: "ts/security/child-process-exec", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Confidence: protocol.ConfidenceMedium,
				File: filePath, Line: lineNum, Message: "child_process.exec() invokes a shell and risks command injection",
				Evidence: rawTrimmed, Remediation: "Use execFile() or spawn() with an explicit argument array.",
			})
		}
		if reDOMXSS.MatchString(trimmed) {
			out = append(out, protocol.Finding{
				Rule: "ts/security/dom-xss", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Potential DOM XSS via HTML sink assignment",
				Evidence: rawTrimmed, Remediation: "Use textContent or sanitize HTML with DOMPurify before rendering.",
			})
		}
	}
	return out
}
