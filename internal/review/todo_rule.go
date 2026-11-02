package review

import (
	"regexp"
	"strconv"
	"strings"
)

type TodoRule struct{}

var hunkHeader = regexp.MustCompile(
	`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`,
)

func (TodoRule) Name() string {
	return "todo-marker"
}

func (TodoRule) Check(diff string) []Finding {
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

		if strings.HasPrefix(line, "+") &&
			!strings.HasPrefix(line, "+++") {
			if strings.Contains(strings.ToUpper(line), "TODO") {
				findings = append(findings, Finding{
					Rule:        "todo-marker",
					Severity:    "low",
					File:        file,
					Line:        lineNumber,
					Message:     "Added line contains a TODO marker",
					Remediation: "Resolve the TODO or track it in an issue tracker.",
				})
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
