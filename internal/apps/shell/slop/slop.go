package slop

import (
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

// Rules returns all Shell slop detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "shell/slop/missing-strict-mode", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Summary: "Executable shell script lacks strict mode (set -euo pipefail or set -eu)"},
	}
}

// Analyze runs Shell slop detectors.
func Analyze(filePath string, lines []string, allowed func(int) bool, isShell bool) []protocol.Finding {
	if !isShell || len(lines) == 0 {
		return nil
	}
	if strings.HasPrefix(lines[0], "#!") && strings.Contains(lines[0], "sh") {
		limit := len(lines)
		if limit > 20 {
			limit = 20
		}
		hasStrict := false
		for _, l := range lines[:limit] {
			if strings.Contains(l, "set -euo pipefail") || strings.Contains(l, "set -eu") {
				hasStrict = true
				break
			}
		}
		if !hasStrict && allowed(1) {
			return []protocol.Finding{{
				Rule: "shell/slop/missing-strict-mode", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Confidence: protocol.ConfidenceMedium,
				File: filePath, Line: 1, Message: "Shell script lacks set -euo pipefail / set -eu strict mode",
				Evidence: strings.TrimSpace(lines[0]), Remediation: "Add 'set -euo pipefail' near the top of the script.",
			}}
		}
	}
	return nil
}
