package review

import (
	"regexp"
	"strconv"
	"strings"
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

			for _, debugPattern := range debugPatterns {
				if debugPattern.pattern.MatchString(addedLine) {
					findings = append(findings, Finding{
						Rule:     "debug-leftover",
						Severity: "medium",
						File:     file,
						Line:     lineNumber,
						Message:  debugPattern.message,
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
