package review

import (
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

// XSSRule flags DOM sinks that inject strings as HTML/script without
// sanitization.
type XSSRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (XSSRule) Name() string {
	return "cross-site-scripting"
}

var xssPatterns = []struct {
	language language.CodeLanguage
	pattern  *regexp.Regexp
	message  string
}{
	{
		language: language.LanguageJavaScript,
		pattern:  regexp.MustCompile(`\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(|document\.write(?:ln)?s?\s*\(`),
		message:  "HTML assigned to a DOM sink without sanitization; use textContent or sanitize",
	},
	{
		language: language.LanguageTypeScript,
		pattern:  regexp.MustCompile(`\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(|document\.write(?:ln)?s?\s*\(|dangerouslySetInnerHTML`),
		message:  "HTML assigned to a DOM sink without sanitization; use textContent or sanitize",
	},
	{
		language: language.LanguageJavaScript,
		pattern:  regexp.MustCompile(`\bdangerouslySetInnerHTML\b`),
		message:  "dangerouslySetInnerHTML bypasses React escaping; ensure the value is sanitized",
	},
}

// xssTemplatePattern covers template syntaxes in Vue/Svelte/Angular files,
// which have no dedicated CodeLanguage.
var xssTemplatePattern = regexp.MustCompile(`\bv-html\s*=|\[innerHTML\]\s*=|\(innerHTML\)\s*=`)

func (r XSSRule) Check(diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		fileLanguage := (language.CodeChecker{}).Language(block.file)
		ext := strings.ToLower(path.Ext(block.file))
		templateFile := ext == ".vue" || ext == ".svelte" || ext == ".html"
		code := string(maskNonCode(block.file, block.text))
		report := func(offset int, message string) {
			line := lineAtOffset(block.firstLine, code, offset)
			key := block.file + ":" + strconv.Itoa(line)
			if seen[key] {
				return
			}
			seen[key] = true
			findings = append(findings, xssFinding(block, code, offset, message))
		}
		for _, xssPattern := range xssPatterns {
			if xssPattern.language != fileLanguage {
				continue
			}
			for _, match := range xssPattern.pattern.FindAllStringIndex(code, -1) {
				if matchTouchesAdded(block, code, match[0], match[1]) {
					report(match[0], xssPattern.message)
				}
			}
		}
		if !templateFile {
			continue
		}
		for _, match := range xssTemplatePattern.FindAllStringIndex(code, -1) {
			if matchTouchesAdded(block, code, match[0], match[1]) {
				report(match[0], "Template renders raw HTML; ensure the bound value is sanitized")
			}
		}
	}
	return findings
}

func xssFinding(block diffSourceBlock, code string, offset int, message string) Finding {
	return Finding{
		Rule:        "cross-site-scripting",
		Severity:    "high",
		File:        block.file,
		Line:        lineAtOffset(block.firstLine, code, offset),
		Message:     message,
		Remediation: "Sanitize HTML with a vetted library (e.g. DOMPurify) or render as text.",
	}
}
