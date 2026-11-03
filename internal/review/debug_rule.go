package review

import (
	"regexp"
)

type DebugRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (DebugRule) Name() string {
	return "debug-leftover"
}

var debugPatterns = []struct {
	pattern *regexp.Regexp
	message string
}{
	{
		pattern: regexp.MustCompile(`\bfmt\.Print(?:ln|f)?\s*\(`),
		message: "Debug print statement detected",
	},
	{
		pattern: regexp.MustCompile(`\bconsole\.log\s*\(`),
		message: "Console log statement detected",
	},
	{
		pattern: regexp.MustCompile(`\bdebugger\s*;?`),
		message: "Debugger statement detected",
	},
}

func (r DebugRule) Check(diff string) []Finding {
	var findings []Finding
	for _, fileDiff := range ParseDiff(diff) {
		blocks := diffSourceBlocksForFile(diff, fileDiff.Path)
		if source, err := readRuleSource(r.RepositoryRoot, fileDiff.Path, r.WorkingTree); err == nil {
			blocks = []diffSourceBlock{fullSourceBlock(fileDiff.Path, source, fileDiff.AddedLines)}
		}
		for _, block := range blocks {
			code := string(maskNonCode(block.file, block.text))
			for _, debugPattern := range debugPatterns {
				for _, match := range debugPattern.pattern.FindAllStringIndex(code, -1) {
					if !matchTouchesAdded(block, code, match[0], match[1]) {
						continue
					}
					findings = append(findings, Finding{
						Rule:        "debug-leftover",
						Severity:    "medium",
						File:        block.file,
						Line:        lineAtOffset(block.firstLine, code, match[0]),
						Message:     debugPattern.message,
						Remediation: "Remove debug output before merging, or replace it with the project's approved logging.",
					})
					break
				}
			}
		}
	}

	return findings
}
