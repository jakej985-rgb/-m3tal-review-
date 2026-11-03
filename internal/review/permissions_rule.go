package review

import (
	"regexp"
	"strconv"
	"strings"
)

type PermissionsRule struct{}

func (PermissionsRule) Name() string {
	return "world-writable-file-mode"
}

var worldWritablePattern = regexp.MustCompile(
	`\b(os\.)?(WriteFile|Mkdir|MkdirAll|OpenFile)\s*\([^)]*\b(0777|0o777)\b`,
)

func (PermissionsRule) Check(diff string) []Finding {
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

			if worldWritablePattern.MatchString(addedLine) {
				findings = append(findings, Finding{
					Rule:        "world-writable-file-mode",
					Severity:    "high",
					File:        file,
					Line:        lineNumber,
					Message:     "File operation uses world-writable permissions (0777)",
					Remediation: "Use more restrictive permissions (e.g., 0644 for files, 0755 for directories).",
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
