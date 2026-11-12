package review

import (
	"regexp"
	"strconv"
	"strings"
)

// SecretRule detects high-confidence credential material that the
// name=value SecurityRule cannot see: PEM private key blocks and well-known
// token formats (cloud keys, SCM tokens, API keys). Unlike SecurityRule it
// scans every changed file, since secrets leak into docs, fixtures, and
// config files as often as into source.
type SecretRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (SecretRule) Name() string {
	return "exposed-secret"
}

// secretTokenPattern uses named groups so findings can name the credential
// type without ever embedding the secret value in the report.
var secretTokenPattern = regexp.MustCompile(
	`\b(?P<aws>(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b` +
		`|\b(?P<github>(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})\b` +
		`|\b(?P<gitlab>glpat-[A-Za-z0-9_-]{15,})\b` +
		`|\b(?P<slack>xox[baprs]-[A-Za-z0-9-]{10,})\b` +
		`|\b(?P<openai>sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,})\b` +
		`|\b(?P<stripe>[sr]k_live_[A-Za-z0-9]{16,})\b` +
		`|\b(?P<google>AIza[0-9A-Za-z_-]{35})\b` +
		`|\b(?P<npm>npm_[A-Za-z0-9]{30,})\b`)

var privateKeyPattern = regexp.MustCompile(
	`(?m)^[ \t]*\-{5}BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?\-{5}[ \t]*$`)

// secretPlaceholderWords mark tokens that are documentation examples or test
// fixtures rather than real credentials.
var secretPlaceholderWords = []string{
	"example", "sample", "dummy", "fake", "test", "your_", "changeme",
	"placeholder", "redacted", "xxxxx", "notreal", "not-a-real",
}

func looksLikePlaceholderToken(token string) bool {
	lower := strings.ToLower(token)
	for _, word := range secretPlaceholderWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

func (r SecretRule) Check(diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		for _, match := range privateKeyPattern.FindAllStringIndex(block.text, -1) {
			if !matchTouchesAdded(block, block.text, match[0], match[1]) {
				continue
			}
			line := lineAtOffset(block.firstLine, block.text, match[0])
			key := block.file + ":" + strconv.Itoa(line)
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, Finding{
				Rule:        "exposed-secret",
				Severity:    "high",
				File:        block.file,
				Line:        line,
				Message:     "Private key material appears in the change",
				Remediation: "Remove the key material and rotate the key. Store secrets outside the repository.",
			})
		}
		// Token-format matches are skipped in test/fixture paths: fixtures
		// legitimately embed token-shaped values (API response captures,
		// mock credentials). PEM private-key blocks above still flag
		// everywhere — key material is unambiguous in any file.
		if isTestSourceFile(block.file) {
			continue
		}
		for _, match := range secretTokenPattern.FindAllStringSubmatchIndex(block.text, -1) {
			// Tokens inside comments are usually documentation examples; tokens
			// inside strings are exactly where real secrets live.
			if offsetInComment(block.file, block.text, match[0]) {
				continue
			}
			if !matchTouchesAdded(block, block.text, match[0], match[1]) {
				continue
			}
			token := block.text[match[0]:match[1]]
			if looksLikePlaceholderToken(token) {
				continue
			}
			line := lineAtOffset(block.firstLine, block.text, match[0])
			key := block.file + ":" + strconv.Itoa(line)
			if seen[key] {
				continue
			}
			seen[key] = true
			// Google API keys (AIza...) are ambiguous: they are embedded
			// public-by-design in many first-party clients (e.g. InnerTube)
			// and in server code alike. A bare source match cannot prove the
			// key is private, so report at medium with a verify-first message
			// instead of the high severity reserved for unambiguous secrets.
			severity, message := "high", "Possible exposed credential: "
			if secretTokenGroup(secretTokenPattern, match) == "google" {
				severity = "medium"
				message = "Possible exposed Google API key (may be a public client key — verify key restrictions): "
			}
			findings = append(findings, Finding{
				Rule:        "exposed-secret",
				Severity:    severity,
				File:        block.file,
				Line:        line,
				Message:     message + secretTokenLabel(secretTokenPattern, match),
				Remediation: "Remove the credential and rotate it. Store secrets outside the repository.",
			})
		}
	}
	return findings
}

// secretTokenGroup returns the name of the named capture group that matched.
func secretTokenGroup(re *regexp.Regexp, match []int) string {
	for i, name := range re.SubexpNames() {
		if i == 0 || name == "" {
			continue
		}
		start, end := match[i*2], match[i*2+1]
		if start >= 0 && end > start {
			return name
		}
	}
	return ""
}

// secretTokenLabel names the matched credential type. Findings deliberately
// never include the token value itself.
func secretTokenLabel(re *regexp.Regexp, match []int) string {
	for i, name := range re.SubexpNames() {
		if i == 0 || name == "" {
			continue
		}
		start, end := match[i*2], match[i*2+1]
		if start >= 0 && end > start {
			return name + " token"
		}
	}
	return "secret"
}
