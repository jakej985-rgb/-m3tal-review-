package review

import (
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

// EvalRule flags dynamic code evaluation, which turns data into executable
// code when the input is attacker-controlled.
type EvalRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (EvalRule) Name() string {
	return "dangerous-eval"
}

// evalPatterns run against the raw block text; the codeMask gate keeps
// matches inside comments and string literals from firing. Raw text is
// required because several patterns must see quote characters, which
// maskNonCode blanks out.
var evalPatterns = []struct {
	language   language.CodeLanguage
	extensions []string
	pattern    *regexp.Regexp
	severity   string
	message    string
}{
	{
		language: language.LanguagePython,
		pattern:  regexp.MustCompile(`\b(?:eval|exec)\s*\(`),
		severity: "high",
		message:  "eval/exec executes arbitrary code; avoid evaluating dynamic input",
	},
	{
		language: language.LanguageJavaScript,
		pattern:  regexp.MustCompile(`\beval\s*\(|\bnew\s+Function\s*\(`),
		severity: "high",
		message:  "eval/new Function executes arbitrary code; avoid evaluating dynamic input",
	},
	{
		language: language.LanguageTypeScript,
		pattern:  regexp.MustCompile(`\beval\s*\(|\bnew\s+Function\s*\(`),
		severity: "high",
		message:  "eval/new Function executes arbitrary code; avoid evaluating dynamic input",
	},
	{
		language: language.LanguageJavaScript,
		pattern:  regexp.MustCompile("\\bsetTimeout\\s*\\(\\s*['\"`]"),
		severity: "medium",
		message:  "setTimeout with a string argument evaluates code; pass a function instead",
	},
	{
		language: language.LanguageTypeScript,
		pattern:  regexp.MustCompile("\\bsetTimeout\\s*\\(\\s*['\"`]"),
		severity: "medium",
		message:  "setTimeout with a string argument evaluates code; pass a function instead",
	},
	{
		language: language.LanguagePHP,
		pattern:  regexp.MustCompile(`\beval\s*\(`),
		severity: "high",
		message:  "eval executes arbitrary code; avoid evaluating dynamic input",
	},
	{
		language: language.LanguagePHP,
		pattern:  regexp.MustCompile(`\bassert\s*\(`),
		severity: "medium",
		message:  "assert() with a string argument evaluates code in older PHP; avoid it for validation",
	},
	{
		// Ruby has no dedicated CodeLanguage; extensions gate it instead.
		language:   language.LanguageUnknown,
		extensions: []string{".rb", ".rake", ".erb"},
		pattern:    regexp.MustCompile("\\bKernel\\.eval|\\.instance_eval\\s*\\(\\s*['\"`]|\\.class_eval\\s*\\(\\s*['\"`]"),
		severity:   "high",
		message:    "eval/instance_eval/class_eval with a string executes arbitrary code",
	},
}

func (r EvalRule) Check(diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		fileLanguage := (language.CodeChecker{}).Language(block.file)
		ext := strings.ToLower(path.Ext(block.file))
		codeMask := sourceCodeMask(block.file, block.text)
		for _, evalPattern := range evalPatterns {
			if evalPattern.language == language.LanguageUnknown {
				matched := false
				for _, candidate := range evalPattern.extensions {
					if ext == candidate {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			} else if evalPattern.language != fileLanguage {
				continue
			}
			for _, match := range evalPattern.pattern.FindAllStringIndex(block.text, -1) {
				if match[0] >= len(codeMask) || !codeMask[match[0]] {
					continue
				}
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
					Rule:        "dangerous-eval",
					Severity:    evalPattern.severity,
					File:        block.file,
					Line:        line,
					Message:     evalPattern.message,
					Remediation: "Replace dynamic evaluation with a parser, template, or explicit dispatch table.",
				})
			}
		}
	}
	return findings
}
