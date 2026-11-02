package review

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type LintRule struct {
	RepositoryRoot string
}

var vetDiagnosticPattern = regexp.MustCompile(`^(?:vet: )?(.+?):(\d+):(\d+): (.+)$`)

func (LintRule) Name() string {
	return "repository-lint"
}

func (r LintRule) Check(_ string) []Finding {
	var findings []Finding

	if r.RepositoryRoot == "" {
		return []Finding{{
			Rule:     r.Name(),
			Severity: "high",
			Message:  "Repository root is not configured for lint checks",
		}}
	}

	formatCmd := exec.Command("gofmt", "-l", ".")
	formatCmd.Dir = r.RepositoryRoot

	formatOutput, formatErr := formatCmd.CombinedOutput()
	if formatErr != nil {
		findings = append(findings, Finding{
			Rule:     r.Name(),
			Severity: "high",
			Message:  "gofmt execution failed: " + strings.TrimSpace(string(formatOutput)),
		})
	} else {
		for _, file := range strings.Split(strings.TrimSpace(string(formatOutput)), "\n") {
			if file == "" {
				continue
			}

			findings = append(findings, Finding{
				Rule:     r.Name(),
				Severity: "medium",
				File:     filepath.ToSlash(file),
				Message:  "File is not formatted; run gofmt",
			})
		}
	}

	vetCmd := exec.Command("go", "vet", "./...")
	vetCmd.Dir = r.RepositoryRoot

	vetOutput, vetErr := vetCmd.CombinedOutput()
	if vetErr != nil {
		parsed := false

		for _, line := range strings.Split(string(vetOutput), "\n") {
			line = strings.TrimSpace(line)
			match := vetDiagnosticPattern.FindStringSubmatch(line)
			if match == nil {
				continue
			}

			lineNumber, err := parsePositiveInt(match[2])
			if err != nil {
				continue
			}

			findings = append(findings, Finding{
				Rule:     r.Name(),
				Severity: "high",
				File:     filepath.ToSlash(strings.TrimPrefix(match[1], "./")),
				Line:     lineNumber,
				Message:  "go vet: " + match[4],
			})
			parsed = true
		}

		if !parsed {
			findings = append(findings, Finding{
				Rule:     r.Name(),
				Severity: "high",
				Message:  "go vet failed: " + strings.TrimSpace(string(vetOutput)),
			})
		}
	}

	return findings
}

func parsePositiveInt(value string) (int, error) {
	var number int
	_, err := fmt.Sscanf(value, "%d", &number)
	return number, err
}
