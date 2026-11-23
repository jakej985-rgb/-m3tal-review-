package review

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

var (
	hostnameAssignRe        = regexp.MustCompile(`\b([a-zA-Z0-9_]+)\s*(?::=|=)\s*([a-zA-Z0-9_.]+)\.Hostname\(\)`)
	netParseIPRe            = regexp.MustCompile(`\b([a-zA-Z0-9_]+)\s*(?::=|=)\s*net\.ParseIP\s*\(\s*([^)\n]+)\s*\)`)
	inlineNetParseIPCheckRe = regexp.MustCompile(`\bnet\.ParseIP\s*\(\s*([^)\n]+(?:\.[a-zA-Z0-9_]+\(\))?)\s*\)\s*\.\s*(?:IsLoopback|IsPrivate|IsGlobalUnicast|IsInterfaceLocalMulticast|IsLinkLocalMulticast|IsLinkLocalUnicast|IsMulticast|IsUnspecified)\s*\(`)
	ipNilGuardRe            = regexp.MustCompile(`(?i)(?:==\s*nil|nil\s*==|!\s*[a-zA-Z0-9_]+)`)
)

// DNSRebindingRule detects naive net.ParseIP validation on URL hostnames that allows
// DNS rebinding SSRF because net.ParseIP returns nil for domain names without erroring.
type DNSRebindingRule struct {
	ruleRuntime
}

func (r *DNSRebindingRule) Name() string { return "dns-rebinding-ssrf" }

func (r *DNSRebindingRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	negatedCheckRe = regexp.MustCompile(
		`(?:\b!\s*(?:net\.ParseIP\s*\(.*?\)|[a-zA-Z0-9_]+)\s*\.\s*Is[A-Z]\w*\s*\(|!\s*\([^)]*\.Is[A-Z]\w*\s*\(|\b(?:net\.ParseIP\s*\(.*?\)|[a-zA-Z0-9_]+)\s*\.\s*Is[A-Z]\w*\s*\([^)]*\)\s*==\s*false|\b(?:net\.ParseIP\s*\(.*?\)|[a-zA-Z0-9_]+)\s*\.\s*Is[A-Z]\w*\s*\([^)]*\)\s*!=\s*true)`,
	)
	returnPredicateRe = regexp.MustCompile(
		`\breturn\s+(?:[^;\n]*\b)?(?:net\.ParseIP\s*\(.*?\)|[a-zA-Z0-9_]+)\s*\.\s*Is[A-Z]\w*\s*\(`,
	)
	rejectReturnRe = regexp.MustCompile(
		`(?:\breturn\s+(?:nil\s*,\s*|[^;\n,]+\s*,\s*)*(?:errors\.|fmt\.Errorf|err\b|[a-zA-Z0-9_]*err[a-zA-Z0-9_]*\b|false\b)|http\.Error\b|\bpanic\s*\()`,
	)
	acceptReturnRe = regexp.MustCompile(
		`(?:\breturn\s+nil\s*(?:;.*)?$|\breturn\s+true\s*(?:;.*)?$|\breturn\s+[^;\n,]+\s*,\s*nil\s*(?:;.*)?$)`,
	)
)

func isAllowlistContext(line string, lines []string, idx int) bool {
	// 1. Returning the check as a boolean predicate (e.g. return net.ParseIP(...).IsLoopback())
	if returnPredicateRe.MatchString(line) {
		return true
	}

	// 2. Negated check applied directly to the IP predicate:
	// e.g. if !net.ParseIP(u.Hostname()).IsLoopback() or if net.ParseIP(...).IsLoopback() == false
	// These require the IP property to be true, rejecting non-matching hosts (domain names).
	if negatedCheckRe.MatchString(line) {
		return true
	}

	// 3. Positive if guard: inspect whether the guarded block accepts or rejects.
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "if ") || strings.HasPrefix(trimmed, "if(") {
		for k := idx; k < len(lines) && k < idx+6; k++ {
			bodyLine := strings.TrimSpace(lines[k])
			if rejectReturnRe.MatchString(bodyLine) {
				// The branch rejects the host (e.g. return nil, fmt.Errorf(...) or http.Error).
				// This is a denylist guard where non-matching domain names bypass it.
				return false
			}
			if acceptReturnRe.MatchString(bodyLine) {
				// The branch accepts the host (e.g. bare return nil or return true).
				// This is an allowlist guard.
				return true
			}
			if strings.Contains(bodyLine, "}") && k > idx {
				break
			}
		}
	}
	return false
}

func (r *DNSRebindingRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if IsTestOrFixtureFile(block.file) {
			continue
		}
		if (language.CodeChecker{}).Language(block.file) != language.LanguageGo {
			continue
		}

		code := string(maskNonCode(block.file, block.text))
		lines := strings.Split(code, "\n")
		rawLines := strings.Split(block.text, "\n")

		type hostSource struct {
			varName string
			lineIdx int
		}

		inFunc := false
		var currentHosts []hostSource

		for i, line := range lines {
			lineNum := block.firstLine + i

			if strings.HasPrefix(strings.TrimSpace(line), "func ") {
				inFunc = true
				currentHosts = nil
			}

			if !inFunc {
				continue
			}

			// Check for hostname assignments: host := u.Hostname()
			if m := hostnameAssignRe.FindStringSubmatch(line); len(m) > 1 {
				currentHosts = append(currentHosts, hostSource{varName: m[1], lineIdx: i})
			}

			// Check for direct parse: ip := net.ParseIP(u.Hostname())
			// or variable parse: ip := net.ParseIP(host)
			if m := netParseIPRe.FindStringSubmatch(line); len(m) > 2 {
				ipVar := m[1]
				arg := strings.TrimSpace(m[2])

				isHostnameParse := false
				if strings.Contains(arg, ".Hostname") {
					isHostnameParse = true
				} else {
					for _, h := range currentHosts {
						if arg == h.varName {
							isHostnameParse = true
							break
						}
					}
				}

				if isHostnameParse {
					// Check subsequent lines in function (up to 30 lines) for ipVar.(IsLoopback|IsPrivate)
					end := i + 30
					if end > len(lines) {
						end = len(lines)
					}

					ipCheckRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(ipVar) + `\s*\.\s*(?:IsLoopback|IsPrivate)\s*\(`)
					ipNilRe := regexp.MustCompile(`\b(?:` + regexp.QuoteMeta(ipVar) + `\s*==\s*nil|nil\s*==\s*` + regexp.QuoteMeta(ipVar) + `)\b`)
					hasIPCheck := false
					checkLine := 0
					hasNilGuard := false

					for k := i; k < end; k++ {
						checkTrimmed := strings.TrimSpace(lines[k])
						if k > i && strings.HasPrefix(checkTrimmed, "func ") {
							break
						}
						// Check if nil is safely guarded before or alongside IsLoopback/IsPrivate
						if ipNilRe.MatchString(lines[k]) {
							hasNilGuard = true
						}
						if ipCheckRe.MatchString(lines[k]) {
							if isAllowlistContext(lines[k], lines, k) {
								continue
							}
							if strings.Contains(lines[k], "!"+ipVar+".") || strings.Contains(lines[k], "! "+ipVar+".") {
								continue
							}
							hasIPCheck = true
							checkLine = block.firstLine + k
							break
						}
					}

					if hasIPCheck && !hasNilGuard {
						touchesAdded := block.addedLines[lineNum] || (checkLine > 0 && block.addedLines[checkLine])
						if !touchesAdded {
							continue
						}
						key := fmt.Sprintf("%s:%d:dns-rebinding-ssrf", block.file, lineNum)
						if seen[key] {
							continue
						}
						seen[key] = true

						snippet := ""
						if i < len(rawLines) {
							snippet = fmt.Sprintf("[%s:%d] (go)\n> %s\n", block.file, lineNum, strings.TrimSpace(rawLines[i]))
						}

						findings = append(findings, Finding{
							Rule:        "dns-rebinding-ssrf",
							Severity:    "high",
							Category:    "security",
							File:        block.file,
							Line:        lineNum,
							Message:     "net.ParseIP on URL hostname misses domain names (nil return); vulnerable to DNS rebinding SSRF",
							Remediation: "Ensure hostnames are resolved to IPs at dial time and validated against private CIDRs; net.ParseIP returns nil for domain names and allows DNS rebinding.",
							Confidence:  "High",
							Snippet:     snippet,
							Explanation: &model.FindingExplanation{
								RuleRationale:   "net.ParseIP returns nil for domain names. Checking IsLoopback() or IsPrivate() on a parsed hostname bypasses validation for public domain names, leaving the service vulnerable to DNS rebinding SSRF.",
								EvidenceSummary: fmt.Sprintf("Hostname parsed with net.ParseIP and checked for loopback/private IP without nil validation on line %d.", lineNum),
								EvidenceKind:    "security-defect",
							},
						})
					}
				}
			}

			// Check for inline check: net.ParseIP(u.Hostname()).IsPrivate() or net.ParseIP(host).IsLoopback()
			if m := inlineNetParseIPCheckRe.FindStringSubmatch(line); len(m) > 1 {
				if isAllowlistContext(line, lines, i) {
					continue
				}
				if strings.Contains(line, "!"+m[0]) || strings.Contains(line, "! "+m[0]) {
					continue
				}
				arg := strings.TrimSpace(m[1])
				isHostnameParse := false
				if strings.Contains(arg, ".Hostname") {
					isHostnameParse = true
				} else {
					for _, h := range currentHosts {
						if arg == h.varName {
							isHostnameParse = true
							break
						}
					}
				}

				if isHostnameParse && block.addedLines[lineNum] {
					key := fmt.Sprintf("%s:%d:dns-rebinding-ssrf", block.file, lineNum)
					if !seen[key] {
						seen[key] = true
						snippet := ""
						if i < len(rawLines) {
							snippet = fmt.Sprintf("[%s:%d] (go)\n> %s\n", block.file, lineNum, strings.TrimSpace(rawLines[i]))
						}
						findings = append(findings, Finding{
							Rule:        "dns-rebinding-ssrf",
							Severity:    "high",
							Category:    "security",
							File:        block.file,
							Line:        lineNum,
							Message:     "net.ParseIP on URL hostname misses domain names (nil return); vulnerable to DNS rebinding SSRF",
							Remediation: "Ensure hostnames are resolved to IPs at dial time and validated against private CIDRs; net.ParseIP returns nil for domain names and allows DNS rebinding.",
							Confidence:  "High",
							Snippet:     snippet,
							Explanation: &model.FindingExplanation{
								RuleRationale:   "net.ParseIP returns nil for domain names. Calling IsLoopback() or IsPrivate() directly on net.ParseIP result misses domain names and allows DNS rebinding SSRF.",
								EvidenceSummary: fmt.Sprintf("Inline net.ParseIP check on hostname without nil validation on line %d.", lineNum),
								EvidenceKind:    "security-defect",
							},
						})
					}
				}
			}
		}
	}
	return findings
}
