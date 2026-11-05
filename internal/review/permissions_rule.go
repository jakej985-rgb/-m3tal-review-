package review

import (
	"regexp"
	"strconv"
)

type PermissionsRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (PermissionsRule) Name() string {
	return "world-writable-file-mode"
}

var worldWritablePattern = regexp.MustCompile(
	`\b(?:(?:os\.)?(?:WriteFile|Mkdir|MkdirAll|OpenFile|Chmod)|[A-Za-z_]\w*\.Chmod)\s*\((?:[^()]|\([^()]*\))*?\b(0[0-7]{3,4}|0o[0-7]{3,4}|os\.ModePerm)\b`,
)

func (r PermissionsRule) Check(diff string) []Finding {
	var findings []Finding
	for _, fileDiff := range ParseDiff(diff) {
		// Performance optimization: Generate diff source blocks directly from fileDiff
		// instead of re-parsing the entire diff and scanning for fileDiff.Path.
		blocks := fileDiffSourceBlocks(fileDiff)
		if source, err := readRuleSource(r.RepositoryRoot, fileDiff.Path, r.WorkingTree); err == nil {
			blocks = []diffSourceBlock{fullSourceBlock(fileDiff.Path, source, fileDiff.AddedLines)}
		}
		for _, block := range blocks {
			code := string(maskNonCode(block.file, block.text))
			for _, match := range worldWritablePattern.FindAllStringSubmatchIndex(code, -1) {
				mode := code[match[2]:match[3]]
				if !isWorldWritableMode(mode) || !matchTouchesAdded(block, code, match[0], match[1]) {
					continue
				}
				findings = append(findings, Finding{
					Rule:        "world-writable-file-mode",
					Severity:    "high",
					File:        block.file,
					Line:        lineAtOffset(block.firstLine, code, match[2]),
					Message:     "File operation grants world-write permission",
					Remediation: "Use more restrictive permissions (e.g., 0644 for files, 0755 for directories).",
				})
			}
		}
	}
	return findings
}

func isWorldWritableMode(mode string) bool {
	if mode == "os.ModePerm" {
		return true
	}
	if len(mode) < 2 || mode[0] != '0' {
		return false
	}
	digits := mode[1:]
	if len(mode) > 1 && mode[1] == 'o' {
		digits = mode[2:]
	} else if len(digits) < 3 {
		return false
	}
	value, err := strconv.ParseUint(digits, 8, 32)
	return err == nil && value&0o002 != 0
}
