package bug

import (
	"path"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var reUnpinnedPkgJSON = regexp.MustCompile(`"([^"]+)"\s*:\s*"(\*|latest)"`)

// Rules returns all Repo bug detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "repo/bug/unpinned-dependency", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Summary: "Dependency version is unpinned (* or latest)"},
	}
}

// Analyze runs Repo bug detectors.
func Analyze(filePath string, lines []string, allowed func(int) bool) []protocol.Finding {
	base := path.Base(filePath)
	isPkgJSON := base == "package.json"
	isReqTxt := base == "requirements.txt"
	if !isPkgJSON && !isReqTxt {
		return nil
	}
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
		if isPkgJSON && reUnpinnedPkgJSON.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "repo/bug/unpinned-dependency", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Dependency uses wildcard (*) or latest version",
				Evidence: trimmed, Remediation: "Pin the dependency to a specific semver range.",
			})
		}
		if isReqTxt && !strings.Contains(trimmed, "==") && !strings.HasPrefix(trimmed, "-") {
			out = append(out, protocol.Finding{
				Rule: "repo/bug/unpinned-dependency", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Confidence: protocol.ConfidenceMedium,
				File: filePath, Line: lineNum, Message: "Python requirement is not pinned with ==",
				Evidence: trimmed, Remediation: "Pin exact versions (e.g., package==1.2.3) for reproducible builds.",
			})
		}
	}
	return out
}
