package review

import (
	"context"
	"path"
	"path/filepath"
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
	switch value {
	case "tokenizer", "bpe", "wordpiece", "unigram", "checkpoint", "model_card", "manifest", "archive":
		return true
	}
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
	// Masked values such as "xxxxxxxx", "********" or UI masks like "••••".
	return strings.Trim(value, "x*•·.-_") == ""
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

// isGeneratedDependencyFile reports whether the path is a generated lockfile
// or checksum manifest. These contain package names, version ranges, and
// integrity hashes that look like credentials but are not.
func isGeneratedDependencyFile(file string) bool {
	base := strings.ToLower(path.Base(file))
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
		"go.sum", "cargo.lock", "gemfile.lock", "composer.lock", "poetry.lock",
		"pubspec.lock", "packages.lock.json", "flake.lock":
		return true
	}
	return strings.HasSuffix(base, ".sum")
}

// IsTestOrFixtureFile reports whether the path is a test file, test suite,
// test data, or fixture. Test files legitimately contain mock tokens, dummy URLs,
// testing parsers, and intentional vulnerabilities to exercise test cases.
func IsTestOrFixtureFile(file string) bool {
	base := strings.ToLower(path.Base(file))
	slashPath := "/" + strings.TrimPrefix(filepath.ToSlash(file), "/")
	lower := strings.ToLower(slashPath)
	// Directory segments across ecosystems: Go testdata/, Python tests/ and tests/data/,
	// generic fixtures/, JS/TS test/, __tests__/, specs/.
	for _, seg := range []string{"/testdata/", "/tests/", "/test/", "/fixtures/", "/fixture/", "/specs/", "/spec/", "/__tests__/"} {
		if strings.Contains(lower, seg) {
			return true
		}
	}
	// Python test files frequently start with "test_" (e.g. test_fuzz.py)
	if strings.HasPrefix(base, "test_") && (strings.HasSuffix(base, ".py") || strings.HasSuffix(base, ".pyc")) {
		return true
	}
	for _, suffix := range []string{
		"_test.go", "_test.py", "_test.rb", "_test.java", "_test.kt",
		"_test.rs", "_test.c", "_test.cpp", "_test.cc",
		".test.js", ".test.ts", ".test.jsx", ".test.tsx",
		".spec.js", ".spec.ts", ".spec.jsx", ".spec.tsx",
	} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

func isTestSourceFile(file string) bool {
	return IsTestOrFixtureFile(file)
}

func (r SecurityRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r SecurityRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if len(fileDiff.AddedLines) == 0 || isGeneratedDependencyFile(fileDiff.Path) || isTestSourceFile(fileDiff.Path) {
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
				// Member access (obj.token, key.secret) reads a field rather than
				// assigning a literal; skip it to avoid JSX/template FPs.
				if nameStart > 0 && (block.text[nameStart-1] == '.' || block.text[nameStart-1] == ']') {
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
				// Constants named *TOKEN*/*SECRET* that hold URLs (endpoint,
				// callback, verification URLs) are not credentials.
				if strings.Contains(value, "://") {
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
		if !isConfigStyleFile(added.File) || isGeneratedDependencyFile(added.File) || isTestSourceFile(added.File) || isCommentOnlyLine(added.File, added.Text) {
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

func isCredentialName(name string) bool {
	lowerRaw := strings.ToLower(name)
	// Check for NLP/lexer/compiler tokens that are not auth credentials
	if strings.Contains(lowerRaw, "tokens") ||
		strings.Contains(lowerRaw, "tokenizer") ||
		strings.Contains(lowerRaw, "tokenize") ||
		strings.Contains(lowerRaw, "tokenization") {
		return false
	}
	for _, nonCredPrefix := range []string{"max", "min", "num", "total", "count", "input", "output", "prompt", "completion"} {
		if strings.HasPrefix(lowerRaw, nonCredPrefix+"_") || strings.HasPrefix(lowerRaw, nonCredPrefix) {
			if strings.Contains(lowerRaw, "token") {
				return false
			}
		}
	}
	// Check for suffixes indicating metadata, types, counts, or strategies rather than credential secrets
	for _, nonCredSuffix := range []string{
		"type", "kind", "id", "ids", "count", "strategy", "role",
		"stream", "limit", "max", "len", "length", "pos", "index",
		"offset", "size", "rate", "cost", "budget", "sec",
	} {
		if strings.HasSuffix(lowerRaw, nonCredSuffix) || strings.HasSuffix(lowerRaw, "_"+nonCredSuffix) {
			return false
		}
	}
	// Lexer token constants (e.g. TokenEOF, TokenWhitespace, TokenNewline)
	if strings.HasPrefix(lowerRaw, "token") {
		switch lowerRaw {
		case "tokeneof", "tokenwhitespace", "tokennewline", "tokenerror",
			"tokenident", "tokenkeyword", "tokenoperator", "tokenliteral",
			"tokenstring", "tokenint", "tokenfloat", "tokencomment":
			return false
		}
	}

	norm := strings.NewReplacer("_", "", "-", "", ".", "").Replace(lowerRaw)
	for _, marker := range []string{"password", "passwd", "apikey", "accesskey", "privatekey", "token", "secret"} {
		if strings.Contains(norm, marker) {
			return true
		}
	}
	return false
}
