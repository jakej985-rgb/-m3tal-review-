package review

import (
	"path"
	"regexp"
	"strings"
)

type SecurityRule struct{}

func (SecurityRule) Name() string {
	return "hardcoded-credential"
}

// credentialPattern matches `name = "value"` style assignments. It accepts:
//   - an optionally quoted name (JSON/YAML keys such as "api_token": "...")
//   - an optional type between name and operator (var dbPassword string = "...")
//   - "=", ":" or ":=" operators
//   - double-quoted, single-quoted or backtick-quoted values of 8+ characters
var credentialPattern = regexp.MustCompile(
	`(?i)["']?\b([A-Za-z_][A-Za-z0-9_.-]*)["']?` +
		`(?:\s+[A-Za-z_][A-Za-z0-9_.\[\]*]*)?` +
		`\s*(?::=|[:=])\s*` +
		"(?:\"([^\"]{8,})\"|'([^']{8,})'|`([^`]{8,})`)")

// unquotedCredentialPattern matches `NAME=value` / `name: value` lines in
// config-style files, where values are normally not quoted. Values are limited
// to characters that appear in real secrets, so code such as `os.Getenv(` or
// `${VAR}` does not match.
var unquotedCredentialPattern = regexp.MustCompile(
	`(?i)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*([A-Za-z0-9+/=_.~@%^&*!-]{8,})\s*(?:#.*)?$`)

// placeholderSubstrings are words that only appear in obvious placeholders.
var placeholderSubstrings = []string{
	"your_",
	"your-",
	"changeme",
	"change_me",
	"replace_me",
	"placeholder",
}

// placeholderPrefixes only count at the start of the value, so a real secret
// that merely contains "example" is still reported.
var placeholderPrefixes = []string{
	"example",
	"<",
	"${",
	"{{",
	"$(",
}

func isPlaceholderValue(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, p := range placeholderSubstrings {
		if strings.Contains(value, p) {
			return true
		}
	}
	for _, p := range placeholderPrefixes {
		if strings.HasPrefix(value, p) {
			return true
		}
	}
	// Masked values such as "xxxxxxxx" or "********".
	return strings.Trim(value, "x*.") == ""
}

func isConfigStyleFile(file string) bool {
	base := strings.ToLower(path.Base(file))
	if base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env") {
		return true
	}
	switch path.Ext(base) {
	case ".yml", ".yaml", ".properties", ".ini", ".conf", ".cfg", ".toml":
		return true
	}
	return false
}

func (SecurityRule) Check(diff string) []Finding {
	var findings []Finding
	for _, added := range AddedDiffLines(diff) {
		name, value := findCredential(added.File, added.Text)
		if name == "" || isPlaceholderValue(value) {
			continue
		}

		findings = append(findings, Finding{
			Rule:        "hardcoded-credential",
			Severity:    "high",
			File:        added.File,
			Line:        added.Line,
			Message:     "Possible hardcoded credential assigned to " + name,
			Remediation: "Remove hardcoded credentials. Use environment variables or a secret management system.",
		})
	}
	return findings
}

// findCredential returns the credential-like name and its value from a line,
// or empty strings when the line has none.
func findCredential(file, text string) (string, string) {
	for _, match := range credentialPattern.FindAllStringSubmatch(text, -1) {
		if !isCredentialName(match[1]) {
			continue
		}
		for _, value := range match[2:] {
			if value != "" {
				return match[1], value
			}
		}
	}
	if isConfigStyleFile(file) {
		if match := unquotedCredentialPattern.FindStringSubmatch(text); match != nil && isCredentialName(match[1]) {
			return match[1], match[2]
		}
	}
	return "", ""
}

func isCredentialName(name string) bool {
	name = strings.ToLower(name)
	name = strings.NewReplacer("_", "", "-", "", ".", "").Replace(name)
	for _, marker := range []string{"password", "passwd", "apikey", "token", "secret"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}
