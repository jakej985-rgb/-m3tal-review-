package review

import (
	"regexp"
	"strconv"
	"strings"
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
		pattern: regexp.MustCompile(`\bexec\.Command\s*\(\s*"(?:sh|bash|zsh|dash)"\s*,\s*"-[a-zA-Z]*c[a-zA-Z]*"`),
		message: "Shell command executed through a command-string flag; review for untrusted input",
	},
}

func (ShellRule) Check(diff string) []Finding {
	var findings []Finding

	var file string
	lineNumber := 0

	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "+++ b/") {
			file = strings.TrimPrefix(line, "+++ b/")
			continue
		}

		if matches := hunkHeader.FindStringSubmatch(line); matches != nil {
			lineNumber, _ = strconv.Atoi(matches[1])
			continue
		}

		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			addedLine := strings.TrimPrefix(line, "+")

			for _, shellPattern := range riskyShellPatterns {
				if shellPattern.pattern.MatchString(addedLine) {
					findings = append(findings, Finding{
						Rule:        "risky-shell-execution",
						Severity:    "high",
						File:        file,
						Line:        lineNumber,
						Message:     shellPattern.message,
						Remediation: "Avoid executing shells with untrusted input. Use direct binary execution with safely separated arguments.",
					})
					break
				}
			}

			lineNumber++
			continue
		}

		if strings.HasPrefix(line, " ") {
			lineNumber++
		}
	}

	return findings
}
