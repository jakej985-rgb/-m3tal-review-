package review

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

// langPattern binds a regex to a code language for pattern-based rules.
type langPattern struct {
	language language.CodeLanguage
	pattern  *regexp.Regexp
	message  string
}

// ruleRuntime carries the per-run context shared by the generic rules.
type ruleRuntime struct {
	repositoryRoot string
	workingTree    bool
}

// EnableWorkingTree switches the rule to read working-tree sources.
func (r *ruleRuntime) EnableWorkingTree() { r.workingTree = true }

// WorkingTreeAware is implemented by rules that can switch to working-tree
// source reads for audit mode.
type WorkingTreeAware interface {
	Rule
	EnableWorkingTree()
}

// patternRule is a generic added-line pattern detector shared by the
// injection, secrets/transport and supply-chain rules.
type patternRule struct {
	ruleRuntime
	name        string
	severity    string
	remediation string
	patterns    []langPattern
	// filePattern, when set, additionally requires the file path to match.
	filePattern *regexp.Regexp
	// skipLine, when set, suppresses findings whose line matches it (used for
	// negated conditions RE2 cannot express, e.g. pinned SHAs).
	skipLine *regexp.Regexp
	// raw matches against unmasked source; required for patterns that must see
	// inside string literals (tokens, headers, URLs, template syntax).
	raw bool
	// anyLanguage allows patterns with LanguageUnknown to apply to all files.
	anyLanguage bool
}

func (r *patternRule) Name() string { return r.name }

func (r *patternRule) Check(diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if r.filePattern != nil && !r.filePattern.MatchString(block.file) {
			continue
		}
		fileLanguage := (language.CodeChecker{}).Language(block.file)
		code := block.text
		if !r.raw {
			code = string(maskNonCode(block.file, block.text))
		}
		for _, p := range r.patterns {
			if p.language != fileLanguage && !(r.anyLanguage && p.language == language.LanguageUnknown) {
				continue
			}
			for _, match := range p.pattern.FindAllStringIndex(code, -1) {
				if !matchTouchesAdded(block, code, match[0], match[1]) {
					continue
				}
				line := lineAtOffset(block.firstLine, code, match[0])
				if r.skipLine != nil && r.skipLine.MatchString(lineContentAt(code, match[0])) {
					continue
				}
				key := block.file + ":" + strconv.Itoa(line)
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, Finding{
					Rule:        r.name,
					Severity:    r.severity,
					File:        block.file,
					Line:        line,
					Message:     p.message,
					Remediation: r.remediation,
				})
			}
		}
	}
	return findings
}

// filenameRule flags files by path alone (e.g. committed secret material).
type filenameRule struct {
	ruleRuntime
	name        string
	severity    string
	message     string
	remediation string
	pattern     *regexp.Regexp
}

func (r *filenameRule) Name() string { return r.name }

func (r *filenameRule) Check(diff string) []Finding {
	var findings []Finding
	for _, fileDiff := range ParseDiff(diff) {
		if !r.pattern.MatchString(filepath.ToSlash(fileDiff.Path)) {
			continue
		}
		if len(fileDiff.AddedLines) == 0 {
			continue
		}
		line := fileDiff.AddedLines[0]
		findings = append(findings, Finding{
			Rule:        r.name,
			Severity:    r.severity,
			File:        fileDiff.Path,
			Line:        line,
			Message:     r.message,
			Remediation: r.remediation,
		})
	}
	return findings
}

// lineRule scans added raw lines (unmasked) for constructs that live in
// non-code files (Dockerfile, workflows, shell scripts).
type lineRule struct {
	ruleRuntime
	name        string
	severity    string
	message     string
	remediation string
	filePattern *regexp.Regexp
	pattern     *regexp.Regexp
}

func (r *lineRule) Name() string { return r.name }

func (r *lineRule) Check(diff string) []Finding {
	var findings []Finding
	for _, fileDiff := range ParseDiff(diff) {
		if r.filePattern != nil && !r.filePattern.MatchString(filepath.ToSlash(fileDiff.Path)) {
			continue
		}
		for _, block := range diffSourceBlocksForFile(diff, fileDiff.Path) {
			code := string(maskNonCode(block.file, block.text))
			for _, match := range r.pattern.FindAllStringIndex(code, -1) {
				if !matchTouchesAdded(block, code, match[0], match[1]) {
					continue
				}
				line := lineAtOffset(block.firstLine, code, match[0])
				findings = append(findings, Finding{
					Rule:        r.name,
					Severity:    r.severity,
					File:        block.file,
					Line:        line,
					Message:     r.message,
					Remediation: r.remediation,
				})
			}
		}
	}
	return findings
}

// lineContentAt returns the single line of source containing offset.
func lineContentAt(source string, offset int) string {
	if offset < 0 {
		offset = 0
	}
	if offset > len(source) {
		offset = len(source)
	}
	start := strings.LastIndexByte(source[:offset], '\n') + 1
	end := strings.IndexByte(source[offset:], '\n')
	if end < 0 {
		return source[start:]
	}
	return source[start : offset+end]
}
