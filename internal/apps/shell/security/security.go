package security

import (
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var (
	rePipeShell  = regexp.MustCompile(`\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|dash)\b`)
	reUnquotedRM = regexp.MustCompile(`\brm\s+-[^\n]*r[^\n]*\s+\$[A-Za-z_][A-Za-z0-9_]*`)
	reWriteAll   = regexp.MustCompile(`^\s*permissions\s*:\s*write-all\s*$`)
	reUses       = regexp.MustCompile(`^\s*(?:-\s*)?uses\s*:\s*([^@\s]+)@([^\s#]+)`)
	reSHA40      = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
)

// Rules returns all Shell/CI security detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "shell/security/pipe-to-shell", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "Piping remote curl/wget output directly into a shell"},
		{ID: "shell/security/unquoted-rm-var", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "Unquoted variable in rm -rf command"},
		{ID: "shell/security/actions-write-all", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "GitHub Actions workflow uses permissions: write-all"},
		{ID: "shell/security/actions-unpinned-uses", Category: protocol.CategorySecurity, Severity: protocol.SeverityMedium, Summary: "GitHub Actions uses tag/branch instead of a 40-char commit SHA"},
	}
}

// Analyze runs Shell/CI security detectors.
func Analyze(filePath string, lines []string, allowed func(int) bool, isWorkflow bool) []protocol.Finding {
	var out []protocol.Finding
	for i, raw := range lines {
		lineNum := i + 1
		if !allowed(lineNum) {
			continue
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if isWorkflow {
			if reWriteAll.MatchString(raw) {
				out = append(out, protocol.Finding{
					Rule: "shell/security/actions-write-all", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Confidence: protocol.ConfidenceHigh,
					File: filePath, Line: lineNum, Message: "Workflow grants write-all permissions",
					Evidence: trimmed, Remediation: "Use least-privilege scoped permissions (e.g., contents: read).",
				})
			}
			if m := reUses.FindStringSubmatch(raw); len(m) == 3 {
				action, ref := m[1], m[2]
				if !strings.HasPrefix(action, "./") && !reSHA40.MatchString(ref) {
					out = append(out, protocol.Finding{
						Rule: "shell/security/actions-unpinned-uses", Category: protocol.CategorySecurity, Severity: protocol.SeverityMedium, Confidence: protocol.ConfidenceHigh,
						File: filePath, Line: lineNum, Message: "Action " + action + "@" + ref + " is not pinned to a 40-char commit SHA",
						Evidence: trimmed, Remediation: "Pin third-party actions to a full 40-character commit SHA.",
					})
				}
			}
			continue
		}
		if rePipeShell.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "shell/security/pipe-to-shell", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Piping remote download directly into a shell",
				Evidence: trimmed, Remediation: "Download, verify checksum/signature, then execute.",
			})
		}
		if reUnquotedRM.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "shell/security/unquoted-rm-var", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Unquoted variable in rm -rf command",
				Evidence: trimmed, Remediation: "Quote the variable (\"$VAR\") and guard against empty values (\"${VAR:?}\").",
			})
		}
	}
	return out
}
