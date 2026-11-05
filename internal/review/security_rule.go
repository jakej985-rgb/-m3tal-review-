package review

import (
	"path"
	"regexp"
	"strconv"
	"strings"
)

type SecurityRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

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
		`(?:[ \t]+[A-Za-z_][A-Za-z0-9_.\[\]*]*)?` +
		`[ \t]*(?::=|[:=])[ \t]*` +
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
	case ".json", ".jsonc", ".yml", ".yaml", ".properties", ".ini", ".conf", ".cfg", ".toml":
		return true
	}
	return false
}

func (r SecurityRule) Check(diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	for _, fileDiff := range ParseDiff(diff) {
		if len(fileDiff.AddedLines) == 0 {
			continue
		}
		// Performance optimization: Generate diff source blocks directly from fileDiff
		// instead of re-parsing the entire diff and scanning for fileDiff.Path.
		blocks := fileDiffSourceBlocks(fileDiff)
		if source, err := readRuleSource(r.RepositoryRoot, fileDiff.Path, r.WorkingTree); err == nil {
			blocks = []diffSourceBlock{fullSourceBlock(fileDiff.Path, source, fileDiff.AddedLines)}
		}
		for _, block := range blocks {
			code := sourceCodeMask(block.file, block.text)
			for _, match := range credentialPattern.FindAllStringSubmatchIndex(block.text, -1) {
				nameStart, nameEnd := match[2], match[3]
				name := block.text[nameStart:nameEnd]
				if !isCredentialName(name) || offsetInComment(block.file, block.text, nameStart) {
					continue
				}
				if !isConfigStyleFile(block.file) && (nameStart >= len(code) || !code[nameStart]) {
					continue
				}
				if !matchTouchesAdded(block, block.text, match[0], match[1]) {
					continue
				}
				value := credentialValueFromMatch(block.text, match)
				if value == "" || isPlaceholderValue(value) {
					continue
				}
				line := lineAtOffset(block.firstLine, block.text, nameStart)
				key := block.file + ":" + strconv.Itoa(line)
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, Finding{Rule: "hardcoded-credential", Severity: "high", File: block.file, Line: line, Message: "Possible hardcoded credential assigned to " + name, Remediation: "Remove hardcoded credentials. Use environment variables or a secret management system."})
			}
		}
	}
	for _, added := range AddedDiffLines(diff) {
		if !isConfigStyleFile(added.File) || isCommentOnlyLine(added.File, added.Text) {
			continue
		}
		name, value := findConfigCredential(added.Text)
		if name == "" || isPlaceholderValue(value) {
			continue
		}
		key := added.File + ":" + strconv.Itoa(added.Line)
		if !seen[key] {
			seen[key] = true
			findings = append(findings, Finding{Rule: "hardcoded-credential", Severity: "high", File: added.File, Line: added.Line, Message: "Possible hardcoded credential assigned to " + name, Remediation: "Remove hardcoded credentials. Use environment variables or a secret management system."})
		}
	}
	return findings
}

func diffSourceBlocksForFile(diff, file string) []diffSourceBlock {
	for _, fileDiff := range ParseDiff(diff) {
		if fileDiff.Path == file {
			return fileDiffSourceBlocks(fileDiff)
		}
	}
	return nil
}

func credentialValueFromMatch(text string, match []int) string {
	for group := 2; group < len(match)/2; group++ {
		start, end := match[group*2], match[group*2+1]
		if start >= 0 && end >= start {
			return text[start:end]
		}
	}
	return ""
}

func findConfigCredential(text string) (string, string) {
	if match := unquotedCredentialPattern.FindStringSubmatch(text); match != nil && isCredentialName(match[1]) {
		return match[1], match[2]
	}
	return "", ""
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
	for _, marker := range []string{"password", "passwd", "apikey", "accesskey", "privatekey", "token", "secret"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}
