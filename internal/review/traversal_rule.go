package review

import (
	"regexp"
	"strconv"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

// TraversalRule flags file and HTTP-serving APIs whose path argument is built
// from request-controlled data without sanitization.
type TraversalRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (TraversalRule) Name() string {
	return "path-traversal"
}

var traversalPatterns = []struct {
	language language.CodeLanguage
	pattern  *regexp.Regexp
	message  string
}{
	{
		language: language.LanguageGo,
		pattern: regexp.MustCompile(
			`\b(?:os\.(?:Open|OpenFile|ReadFile|WriteFile|Create|ReadDir|Stat|Lstat|Remove|Rename)|` +
				`ioutil\.(?:ReadFile|WriteFile|ReadDir)|http\.ServeFile|http\.ServeContent)\s*` +
				`\((?:[^()]|\([^()]*\)){0,120}?(?:\.URL\b|\.RawQuery\b|\.FormValue\s*\(|os\.Args\b|\.PathValue\s*\()`),
		message: "File operation uses request-controlled path data; validate and constrain the path",
	},
	{
		language: language.LanguagePython,
		pattern: regexp.MustCompile(
			`\b(?:open|send_file|send_from_directory|send_static_file)\s*` +
				`\((?:[^()]|\([^()]*\)){0,120}?(?:request\.|flask\.request|\.args\.get|\.form\.get|\.values\.get)`),
		message: "File operation uses request-controlled path data; validate and constrain the path",
	},
	{
		language: language.LanguageJavaScript,
		pattern: regexp.MustCompile(
			`\bfs\.(?:read\w*|write\w*|readdir\w*|stat\w*|access\w*|createReadStream|exists\w*)\s*` +
				`\((?:[^()]|\([^()]*\)){0,120}?(?:req\.(?:url|path|query|params|body)|request\.(?:url|path|query))`),
		message: "File operation uses request-controlled path data; validate and constrain the path",
	},
	{
		language: language.LanguageTypeScript,
		pattern: regexp.MustCompile(
			`\bfs\.(?:read\w*|write\w*|readdir\w*|stat\w*|access\w*|createReadStream|exists\w*)\s*` +
				`\((?:[^()]|\([^()]*\)){0,120}?(?:req\.(?:url|path|query|params|body)|request\.(?:url|path|query))`),
		message: "File operation uses request-controlled path data; validate and constrain the path",
	},
}

func (r TraversalRule) Check(diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		fileLanguage := (language.CodeChecker{}).Language(block.file)
		code := string(maskNonCode(block.file, block.text))
		for _, traversalPattern := range traversalPatterns {
			if traversalPattern.language != fileLanguage {
				continue
			}
			for _, match := range traversalPattern.pattern.FindAllStringIndex(code, -1) {
				if !matchTouchesAdded(block, code, match[0], match[1]) {
					continue
				}
				line := lineAtOffset(block.firstLine, code, match[0])
				key := block.file + ":" + strconv.Itoa(line)
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, Finding{
					Rule:        "path-traversal",
					Severity:    "high",
					File:        block.file,
					Line:        line,
					Message:     traversalPattern.message,
					Remediation: "Validate the path against an allowlist or constrain it to a base directory (e.g. filepath.IsLocal).",
				})
			}
		}
	}
	return findings
}
