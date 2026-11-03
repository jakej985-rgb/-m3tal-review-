package review

import (
	"regexp"
)

type DebugRule struct{}

func (DebugRule) Name() string {
	return "debug-leftover"
}

var debugPatterns = []struct {
	pattern *regexp.Regexp
	message string
}{
	{
		pattern: regexp.MustCompile(`\bfmt\.Print(?:ln|f)?\s*\(`),
		message: "Debug print statement detected",
	},
	{
		pattern: regexp.MustCompile(`\bconsole\.log\s*\(`),
		message: "Console log statement detected",
	},
	{
		pattern: regexp.MustCompile(`\bdebugger\s*;?`),
		message: "Debugger statement detected",
	},
}

func (DebugRule) Check(diff string) []Finding {
	var findings []Finding
	for _, added := range AddedDiffLines(diff) {
		for _, debugPattern := range debugPatterns {
			if debugPattern.pattern.MatchString(added.Text) {
				findings = append(findings, Finding{
					Rule:        "debug-leftover",
					Severity:    "medium",
					File:        added.File,
					Line:        added.Line,
					Message:     debugPattern.message,
					Remediation: "Remove debug output before merging, or replace it with the project's approved logging.",
				})
				break
			}
		}
	}

	return findings
}
