package security

import (
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var (
	reEvalExec   = regexp.MustCompile(`\b(eval|exec)\s*\(`)
	reShellTrue  = regexp.MustCompile(`\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\([^)]*shell\s*=\s*True`)
	reDeser      = regexp.MustCompile(`\b(?:pickle|cPickle|marshal)\.loads?\s*\(`)
	reSQLFString = regexp.MustCompile(`\.(?:execute|executemany|executescript)\s*\(\s*f["']`)
)

// Rules returns all Python security detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "py/security/eval-exec", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "Dynamic code execution via eval/exec"},
		{ID: "py/security/subprocess-shell-true", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "subprocess invoked with shell=True"},
		{ID: "py/security/unsafe-deserialization", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "Unsafe deserialization via pickle/marshal"},
		{ID: "py/security/sql-fstring", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "SQL execute() called with interpolated f-string"},
	}
}

// Analyze runs Python security detectors.
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
		if reEvalExec.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "py/security/eval-exec", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "eval()/exec() executes arbitrary Python code",
				Evidence: trimmed, Remediation: "Use ast.literal_eval() or explicit dispatch.",
			})
		}
		if reShellTrue.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "py/security/subprocess-shell-true", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "subprocess called with shell=True risks command injection",
				Evidence: trimmed, Remediation: "Pass an argument list with shell=False.",
			})
		}
		if reDeser.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "py/security/unsafe-deserialization", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Unsafe deserialization via pickle/marshal",
				Evidence: trimmed, Remediation: "Use json or a schema-validated format instead of pickle/marshal.",
			})
		}
		if reSQLFString.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "py/security/sql-fstring", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "SQL query built with f-string interpolation risks SQL injection",
				Evidence: trimmed, Remediation: "Use parameterized queries instead of f-strings.",
			})
		}
	}
	return out
}
