package review

import (
	"regexp"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

type ShellRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (ShellRule) Name() string {
	return "risky-shell-execution"
}

var riskyShellPatterns = []struct {
	language language.CodeLanguage
	pattern  *regexp.Regexp
	message  string
}{
	{
		language: language.LanguageGo,
		pattern:  regexp.MustCompile(`\bexec\.Command\s*\(\s*"(?:sh|bash|zsh|dash)"\s*,\s*"-c"`),
		message:  "Shell command executed through -c; review for untrusted input",
	},
	{
		language: language.LanguageGo,
		pattern:  regexp.MustCompile(`\bexec\.CommandContext\s*\([^,]+,\s*"(?:sh|bash|zsh|dash)"\s*,\s*"-c"`),
		message:  "Shell command executed through -c; review for untrusted input",
	},
	{
		language: language.LanguageGo,
		pattern:  regexp.MustCompile(`\bexec\.Command\s*\(\s*"(?:sh|bash|zsh|dash)"\s*,\s*"-[a-zA-Z]*c[a-zA-Z]*"`),
		message:  "Shell command executed through a command-string flag; review for untrusted input",
	},
	{
		language: language.LanguageGo,
		pattern:  regexp.MustCompile(`\bexec\.CommandContext\s*\([^,]+,\s*"(?:sh|bash|zsh|dash)"\s*,\s*"-[a-zA-Z]*c[a-zA-Z]*"`),
		message:  "Shell command executed through a command-string flag; review for untrusted input",
	},
	{language: language.LanguagePython, pattern: regexp.MustCompile(`(?s)\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\((?:[^()]|\([^()]*\))*?\bshell\s*=\s*True\b`), message: "Shell command execution enabled; review for untrusted input"},
	{language: language.LanguagePython, pattern: regexp.MustCompile(`\bos\.system\s*\(`), message: "Shell command execution enabled; review for untrusted input"},
	{language: language.LanguageJavaScript, pattern: regexp.MustCompile(`\bchild_process\.(?:exec|execSync)\s*\(`), message: "Shell command execution enabled; review for untrusted input"},
	{language: language.LanguageC, pattern: regexp.MustCompile(`\b(?:system|popen)\s*\(`), message: "Shell command execution enabled; review for untrusted input"},
	{language: language.LanguageCpp, pattern: regexp.MustCompile(`\b(?:system|popen)\s*\(`), message: "Shell command execution enabled; review for untrusted input"},
	{language: language.LanguagePHP, pattern: regexp.MustCompile(`\b(?:shell_exec|exec|system|passthru|popen)\s*\(`), message: "Shell command execution enabled; review for untrusted input"},
}

func (r ShellRule) Check(diff string) []Finding {
	var findings []Finding
	for _, fileDiff := range ParseDiff(diff) {
		blocks := diffSourceBlocksForFile(diff, fileDiff.Path)
		if source, err := readRuleSource(r.RepositoryRoot, fileDiff.Path, r.WorkingTree); err == nil {
			blocks = []diffSourceBlock{fullSourceBlock(fileDiff.Path, source, fileDiff.AddedLines)}
		}
		for _, block := range blocks {
			fileLanguage := (language.CodeChecker{}).Language(block.file)
			maskedCode := maskNonCode(block.file, block.text)
			codeMask := sourceCodeMask(block.file, block.text)
			seenMatches := make(map[int]bool)
			for _, shellPattern := range riskyShellPatterns {
				if shellPattern.language != fileLanguage {
					continue
				}
				search := string(maskedCode)
				if fileLanguage == language.LanguageGo {
					search = block.text // Go's shell and flag arguments are string literals.
				}
				for _, match := range shellPattern.pattern.FindAllStringIndex(search, -1) {
					if seenMatches[match[0]] {
						continue
					}
					if !matchTouchesAdded(block, search, match[0], match[1]) {
						continue
					}
					if fileLanguage == language.LanguageGo && (match[0] >= len(codeMask) || !codeMask[match[0]]) {
						continue
					}
					seenMatches[match[0]] = true
					findings = append(findings, Finding{
						Rule:        "risky-shell-execution",
						Severity:    "high",
						File:        block.file,
						Line:        lineAtOffset(block.firstLine, search, match[0]),
						Message:     shellPattern.message,
						Remediation: "Avoid executing shells with untrusted input. Use direct binary execution with safely separated arguments.",
					})
					break
				}
			}
		}
	}

	return findings
}
