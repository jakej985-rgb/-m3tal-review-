package review

import (
	"regexp"
	"strings"
)

type SecurityRule struct{}

func (SecurityRule) Name() string {
	return "hardcoded-credential"
}

var credentialPattern = regexp.MustCompile(
	`(?i)\b([A-Za-z_][A-Za-z0-9_-]*)\s*[:=]+\s*["']([^"']{8,})["']`)

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
	for _, added := range AddedDiffLines(diff) {
		match := credentialPattern.FindStringSubmatch(added.Text)
		if match == nil || !isCredentialName(match[1]) {
			continue
		}

		value := strings.ToLower(match[2])
		isPlaceholder := false
		for _, placeholder := range credentialPlaceholders {
			if strings.Contains(value, placeholder) {
				isPlaceholder = true
				break
			}
		}
		if isPlaceholder {
			continue
		}

		findings = append(findings, Finding{
			Rule:        "hardcoded-credential",
			Severity:    "high",
			File:        added.File,
			Line:        added.Line,
			Message:     "Possible hardcoded credential assigned to " + match[1],
			Remediation: "Remove hardcoded credentials. Use environment variables or a secret management system.",
		})
	}
	return findings
}

func isCredentialName(name string) bool {
	name = strings.ToLower(name)
	name = strings.NewReplacer("_", "", "-", "").Replace(name)
	for _, marker := range []string{"password", "passwd", "apikey", "token", "secret"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}
