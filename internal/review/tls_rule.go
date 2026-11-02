package review

import (
	"regexp"
	"strconv"
	"strings"
)

type TLSRule struct{}

func (TLSRule) Name() string {
	return "insecure-tls-verification"
}

var insecureTLSPattern = regexp.MustCompile(
	`\bInsecureSkipVerify\s*:\s*true\b`,
)

func (TLSRule) Check(diff string) []Finding {
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

			if insecureTLSPattern.MatchString(addedLine) {
				findings = append(findings, Finding{
					Rule:     "insecure-tls-verification",
					Severity: "high",
					File:     file,
					Line:     lineNumber,
					Message:  "TLS certificate verification is disabled",
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
