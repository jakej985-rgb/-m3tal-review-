package security

import (
	"path"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var (
	reSecret      = regexp.MustCompile(`(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk_live_[A-Za-z0-9]{16,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)`)
	reEnvSecret   = regexp.MustCompile(`^\s*([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)\s*=\s*(.+?)\s*$`)
	rePlaceholder = regexp.MustCompile(`^(?i:changeme|example|placeholder|your[_-]|xxx+|\*+|<[^>]+>|\$\{[^}]+\}|""|'')$`)
	rePublicCIDR  = regexp.MustCompile(`["']0\.0\.0\.0/0["']`)
)

// Rules returns all Repo security detector metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "repo/security/hardcoded-secret", Category: protocol.CategorySecurity, Severity: protocol.SeverityCritical, Summary: "High-confidence credential or private key literal detected"},
		{ID: "repo/security/env-secret-committed", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "Sensitive secret value committed in .env file"},
		{ID: "repo/security/iac-public-cidr", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "Terraform resource allows unrestricted 0.0.0.0/0 CIDR"},
	}
}

// Analyze runs Repo security detectors.
func Analyze(filePath string, lines []string, allowed func(int) bool) []protocol.Finding {
	var out []protocol.Finding
	base := path.Base(filePath)
	isEnv := strings.HasPrefix(base, ".env") && !strings.HasSuffix(base, ".example") && !strings.HasSuffix(base, ".sample")
	isTF := strings.HasSuffix(filePath, ".tf") || strings.HasSuffix(filePath, ".tfvars")

	for i, raw := range lines {
		lineNum := i + 1
		if !allowed(lineNum) {
			continue
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if reSecret.MatchString(raw) {
			ev := trimmed
			if len(ev) > 80 {
				ev = ev[:80]
			}
			out = append(out, protocol.Finding{
				Rule: "repo/security/hardcoded-secret", Category: protocol.CategorySecurity, Severity: protocol.SeverityCritical, Confidence: protocol.ConfidenceHigh,
				File: filePath, Line: lineNum, Message: "Hardcoded credential or private key detected",
				Evidence: ev, Remediation: "Revoke the credential and move it to a secret manager or environment variable.",
			})
		}
		if isEnv {
			if m := reEnvSecret.FindStringSubmatch(raw); len(m) == 3 {
				val := strings.Trim(strings.TrimSpace(m[2]), `"'`)
				if val != "" && !rePlaceholder.MatchString(val) {
					out = append(out, protocol.Finding{
						Rule: "repo/security/env-secret-committed", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Confidence: protocol.ConfidenceHigh,
						File: filePath, Line: lineNum, Message: "Sensitive key " + m[1] + " has a non-placeholder value in " + base,
						Evidence: m[1] + "=***", Remediation: "Remove .env from git and use .env.example with placeholders.",
					})
				}
			}
		}
		if isTF && rePublicCIDR.MatchString(raw) {
			out = append(out, protocol.Finding{
				Rule: "repo/security/iac-public-cidr", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Confidence: protocol.ConfidenceMedium,
				File: filePath, Line: lineNum, Message: "Unrestricted 0.0.0.0/0 CIDR block in Terraform configuration",
				Evidence: trimmed, Remediation: "Restrict cidr_blocks to specific trusted IP ranges.",
			})
		}
	}
	return out
}
