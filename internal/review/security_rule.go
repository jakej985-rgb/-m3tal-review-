package review

import (
	"regexp"
	"strconv"
	"strings"
)

type SecurityRule struct{}

func (SecurityRule) Name() string {
	return "hardcoded-credential"
}

var credentialPattern = regexp.MustCompile(
	`(?i)\b(password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token|secret)\b\s*[:=]+\s*["']([^"']{8,})["']`)

var credentialPlaceholders = []string{
	"your_",
	"your-",
	"changeme",
	"change_me",
	"replace_me",
	"example",
	"placeholder",
	"xxxx",
}

func (SecurityRule) Check(diff string) []Finding {
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

			if match := credentialPattern.FindStringSubmatch(addedLine); match != nil {
				value := strings.ToLower(match[2])
				isPlaceholder := false

				for _, placeholder := range credentialPlaceholders {
					if strings.Contains(value, placeholder) {
						isPlaceholder = true
						break
					}
				}

				if !isPlaceholder {
					findings = append(findings, Finding{
						Rule:        "hardcoded-credential",
						Severity:    "high",
						File:        file,
						Line:        lineNumber,
						Message:     "Possible hardcoded credential assigned to " + match[1],
						Remediation: "Remove hardcoded credentials. Use environment variables or a secret management system.",
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
