package review

import (
	"regexp"
	"strconv"
	"strings"
)

type SlopRule struct{}

func (SlopRule) Name() string {
	return "code-slop"
}

var slopPatterns = []struct {
	pattern     *regexp.Regexp
	message     string
	remediation string
}{
	{
		pattern:     regexp.MustCompile(`==\s*true\b|\btrue\s*==|!=\s*false\b|\bfalse\s*!=`),
		message:     "Redundant boolean comparison",
		remediation: "Remove the explicit comparison to true/false. Use the boolean expression directly.",
	},
	{
		pattern:     regexp.MustCompile(`(?:\t| {4}){4,}`),
		message:     "Excessive indentation (indicates deep nesting)",
		remediation: "Refactor to reduce nesting depth. Consider using early returns or breaking logic into smaller functions.",
	},
	{
		pattern:     regexp.MustCompile(`\{\s*\}`),
		message:     "Empty block",
		remediation: "Remove the empty block or add a comment explaining why it is empty.",
	},
}

func (SlopRule) Check(diff string) []Finding {
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

			// Simple exclusion for comments to reduce false positives
			if strings.HasPrefix(strings.TrimSpace(addedLine), "//") || strings.HasPrefix(strings.TrimSpace(addedLine), "/*") {
				lineNumber++
				continue
			}

			for _, slopPattern := range slopPatterns {
				if slopPattern.pattern.MatchString(addedLine) {
					// Ignore interface{} for empty block rule
					if slopPattern.message == "Empty block" && strings.Contains(addedLine, "interface{}") {
						continue
					}
					// Ignore false positive string literals for empty blocks and boolean comparisons (heuristic)
					if strings.Contains(addedLine, "\"") && (strings.Contains(addedLine, "==") || strings.Contains(addedLine, "{}")) {
						// Note: this is a basic heuristic. A full AST parser would be better but breaks deterministic local text limits.
						continue
					}

					findings = append(findings, Finding{
						Rule:        "code-slop",
						Severity:    "low",
						File:        file,
						Line:        lineNumber,
						Message:     slopPattern.message,
						Remediation: slopPattern.remediation,
					})
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
