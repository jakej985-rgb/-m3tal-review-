package security

import (
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var (
	reUnsafe      = regexp.MustCompile(`\bunsafe\s*(?:\{|fn\b|trait\b|impl\b)`)
	reSafety      = regexp.MustCompile(`(?i)//[/!*]?\s*SAFETY\s*:`)
	reInsecureTLS = regexp.MustCompile(`\.danger_accept_invalid_(?:certs|hostnames)\s*\(\s*true\s*\)`)
)

// Rules returns all Rust security detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "rust/security/unsafe-without-safety", Category: protocol.CategorySecurity, Severity: protocol.SeverityMedium, Summary: "unsafe block or item lacks a // SAFETY: comment"},
		{ID: "rust/security/insecure-tls", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "TLS certificate or hostname verification disabled"},
	}
}

// Analyze runs Rust security detectors.
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
		if reUnsafe.MatchString(raw) {
			start := i - 6
			if start < 0 {
				start = 0
			}
			window := strings.Join(lines[start:i+1], "\n")
			if !reSafety.MatchString(window) {
				out = append(out, protocol.Finding{
					Rule: "rust/security/unsafe-without-safety", Category: protocol.CategorySecurity, Severity: protocol.SeverityMedium, Confidence: protocol.ConfidenceHigh,
					File: filePath, Line: lineNum, Message: "unsafe block or declaration lacks a // SAFETY: rationale comment",
					Evidence: trimmed, Remediation: "Add a // SAFETY: comment explaining the invariants upheld.",
				})
			}
		}
		if reInsecureTLS.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "rust/security/insecure-tls", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "TLS certificate or hostname verification is disabled",
				Evidence: trimmed, Remediation: "Remove danger_accept_invalid_certs/hostnames(true).",
			})
		}
	}
	return out
}
