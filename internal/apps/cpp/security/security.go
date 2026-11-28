package security

import (
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var (
	reUnbounded = regexp.MustCompile(`\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(`)
	reCmdExec   = regexp.MustCompile(`\b(system|popen)\s*\(`)
)

// Rules returns all C/C++ security detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "cpp/security/unbounded-buffer", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "Unbounded C buffer function (strcpy/strcat/sprintf/vsprintf/gets)"},
		{ID: "cpp/security/command-exec", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "Shell command execution via system()/popen()"},
	}
}

// Analyze runs C/C++ security detectors.
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
		if reUnbounded.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "cpp/security/unbounded-buffer", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Unbounded C buffer function risks stack/heap buffer overflow",
				Evidence: trimmed, Remediation: "Use bounded alternatives (snprintf, strnlen/memcpy, std::string).",
			})
		}
		if reCmdExec.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "cpp/security/command-exec", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Confidence: protocol.ConfidenceMedium,
				File: filePath, Line: lineNum, Message: "system()/popen() invokes a shell and risks command injection",
				Evidence: trimmed, Remediation: "Use execve/posix_spawn with an explicit argument vector.",
			})
		}
	}
	return out
}
