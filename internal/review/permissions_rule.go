package review

import (
	"regexp"
	"strconv"
)

type PermissionsRule struct{}

func (PermissionsRule) Name() string {
	return "world-writable-file-mode"
}

var worldWritablePattern = regexp.MustCompile(
	`\b(?:(?:os\.)?(?:WriteFile|Mkdir|MkdirAll|OpenFile|Chmod)|[A-Za-z_]\w*\.Chmod)\s*\([^)]*\b(0[0-7]{3,4}|0o[0-7]{3,4}|os\.ModePerm)\b`,
)

func (PermissionsRule) Check(diff string) []Finding {
	var findings []Finding
	for _, added := range AddedDiffLines(diff) {
		match := worldWritablePattern.FindStringSubmatch(added.Text)
		if match != nil && isWorldWritableMode(match[1]) {
			findings = append(findings, Finding{
				Rule:        "world-writable-file-mode",
				Severity:    "high",
				File:        added.File,
				Line:        added.Line,
				Message:     "File operation uses world-writable permissions (0777)",
				Remediation: "Use more restrictive permissions (e.g., 0644 for files, 0755 for directories).",
			})
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
