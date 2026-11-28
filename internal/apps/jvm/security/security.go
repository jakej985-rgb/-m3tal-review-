package security

import (
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var (
	reDeser = regexp.MustCompile(`\b(ObjectInputStream|XMLDecoder)\s*\(`)
	reExec  = regexp.MustCompile(`Runtime\.getRuntime\(\)\.exec\s*\(`)
)

// Rules returns all JVM security detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "jvm/security/insecure-deserialization", Category: protocol.CategorySecurity, Severity: protocol.SeverityCritical, Summary: "ObjectInputStream/XMLDecoder deserialization without ObjectInputFilter"},
		{ID: "jvm/security/command-injection", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "Runtime.getRuntime().exec() risks command injection"},
	}
}

// Analyze runs JVM security detectors.
func Analyze(filePath, content string, lines []string, allowed func(int) bool) []protocol.Finding {
	var out []protocol.Finding
	hasFilter := strings.Contains(content, "ObjectInputFilter")
	for i, raw := range lines {
		lineNum := i + 1
		if !allowed(lineNum) {
			continue
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if reDeser.MatchString(raw) && !hasFilter {
			out = append(out, protocol.Finding{
				Rule: "jvm/security/insecure-deserialization", Category: protocol.CategorySecurity, Severity: protocol.SeverityCritical, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Unsafe Java deserialization without ObjectInputFilter",
				Evidence: trimmed, Remediation: "Use JSON/Protobuf or configure a strict ObjectInputFilter.",
			})
		}
		if reExec.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "jvm/security/command-injection", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Confidence: protocol.ConfidenceMedium,
				File: filePath, Line: lineNum, Message: "Runtime.getRuntime().exec() risks OS command injection",
				Evidence: trimmed, Remediation: "Use ProcessBuilder with a fixed argument list.",
			})
		}
	}
	return out
}
