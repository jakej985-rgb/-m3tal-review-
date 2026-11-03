package review

import (
	"regexp"
)

type TLSRule struct{}

func (TLSRule) Name() string {
	return "insecure-tls-verification"
}

var insecureTLSPattern = regexp.MustCompile(
	`\bInsecureSkipVerify\s*(?::|=)\s*true\b`,
)

func (TLSRule) Check(diff string) []Finding {
	var findings []Finding
	for _, added := range AddedDiffLines(diff) {
		if insecureTLSPattern.MatchString(added.Text) {
			findings = append(findings, Finding{
				Rule:        "insecure-tls-verification",
				Severity:    "high",
				File:        added.File,
				Line:        added.Line,
				Message:     "TLS certificate verification is disabled",
				Remediation: "Remove InsecureSkipVerify or set it to false to ensure secure connections.",
			})
		}
	}

	return findings
}
