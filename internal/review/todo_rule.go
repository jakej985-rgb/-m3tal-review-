package review

import (
	"strings"
)

type TodoRule struct{}

func (TodoRule) Name() string {
	return "todo-marker"
}

func (TodoRule) Check(diff string) []Finding {
	var findings []Finding

	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "+") &&
			!strings.HasPrefix(line, "+++") &&
			strings.Contains(strings.ToUpper(line), "TODO") {
			findings = append(findings, Finding{
				Rule:     "todo-marker",
				Severity: "low",
				Message:  "Added line contains a TODO marker",
			})
		}
	}

	return findings
}