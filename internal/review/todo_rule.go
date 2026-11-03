package review

import (
	"regexp"
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
	for _, added := range AddedDiffLines(diff) {
		if strings.Contains(strings.ToUpper(added.Text), "TODO") {
			findings = append(findings, Finding{
				Rule:        "todo-marker",
				Severity:    "low",
				File:        added.File,
				Line:        added.Line,
				Message:     "Added line contains a TODO marker",
				Remediation: "Resolve the TODO or create a tracked issue with an owner and follow-up plan.",
			})
		}
	}

	return findings
}
