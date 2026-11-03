package review

import (
	"regexp"
)

type ShellRule struct{}

func (ShellRule) Name() string {
	return "risky-shell-execution"
}

var riskyShellPatterns = []struct {
	pattern *regexp.Regexp
	message string
}{
	{
		pattern: regexp.MustCompile(`\bexec\.Command\s*\(\s*"(?:sh|bash|zsh|dash)"\s*,\s*"-c"`),
		message: "Shell command executed through -c; review for untrusted input",
	},
	{
		pattern: regexp.MustCompile(`\bexec\.CommandContext\s*\([^,\n]+,\s*"(?:sh|bash|zsh|dash)"\s*,\s*"-c"`),
		message: "Shell command executed through -c; review for untrusted input",
	},
	{
		pattern: regexp.MustCompile(`\bexec\.Command\s*\(\s*"(?:sh|bash|zsh|dash)"\s*,\s*"-[a-zA-Z]*c[a-zA-Z]*"`),
		message: "Shell command executed through a command-string flag; review for untrusted input",
	},
	{
		pattern: regexp.MustCompile(`\bexec\.CommandContext\s*\([^,\n]+,\s*"(?:sh|bash|zsh|dash)"\s*,\s*"-[a-zA-Z]*c[a-zA-Z]*"`),
		message: "Shell command executed through a command-string flag; review for untrusted input",
	},
}

func (ShellRule) Check(diff string) []Finding {
	var findings []Finding
	for _, added := range AddedDiffLines(diff) {
		for _, shellPattern := range riskyShellPatterns {
			if shellPattern.pattern.MatchString(added.Text) {
				findings = append(findings, Finding{
					Rule:        "risky-shell-execution",
					Severity:    "high",
					File:        added.File,
					Line:        added.Line,
					Message:     shellPattern.message,
					Remediation: "Avoid executing shells with untrusted input. Use direct binary execution with safely separated arguments.",
				})
				break
			}
		}
	}

	return findings
}
