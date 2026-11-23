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
	rejectReturnRe = regexp.MustCompile(
		`(?:\breturn\s+(?:nil\s*,\s*|[^;\n,]+\s*,\s*)*(?:errors\.|fmt\.Errorf|err\b|[a-zA-Z0-9_]*err[a-zA-Z0-9_]*\b|false\b)|http\.Error\b|\bpanic\s*\()`,
	)
	acceptReturnRe = regexp.MustCompile(
		`(?:\breturn\s+nil\s*(?:;.*)?$|\breturn\s+true\s*(?:;.*)?$|\breturn\s+[^;\n,]+\s*,\s*nil\s*(?:;.*)?$)`,
	)
)

func unwrapParens(s string) string {
	for {
		s = strings.TrimSpace(s)
		if strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
			depth := 0
			wrapsAll := true
			for i, ch := range s {
				if ch == '(' {
					depth++
				} else if ch == ')' {
					depth--
					if depth == 0 && i < len(s)-1 {
						wrapsAll = false
						break
					}
				}
			}
			if wrapsAll && depth == 0 {
				s = s[1 : len(s)-1]
				continue
			}
		}
		break
	}
	return s
}

func findIfBlockEnd(lines []string, ifLine int) int {
	depth := 0
	foundOpen := false
	for k := ifLine; k < len(lines); k++ {
		for _, ch := range lines[k] {
			if ch == '{' {
				depth++
				foundOpen = true
			} else if ch == '}' {
				depth--
				if foundOpen && depth <= 0 {
					return k
				}
			}
		}
	}
	return ifLine
}

func hasRejectingElse(lines []string, endIfLine int) bool {
	elseStart := -1
	for k := endIfLine; k < len(lines) && k <= endIfLine+2; k++ {
		if strings.Contains(lines[k], "else") {
			elseStart = k
			break
		}
	}
	if elseStart == -1 {
		return false
	}
	elseEnd := findIfBlockEnd(lines, elseStart)
	for k := elseStart; k <= elseEnd && k < len(lines); k++ {
		if rejectReturnRe.MatchString(lines[k]) {
			return true
		}
	}
	return false
}

func isReturnIPPredicate(line string) bool {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "return ") && !strings.HasPrefix(trimmed, "return\t") {
		return false
	}
	expr := strings.TrimPrefix(trimmed, "return")
	expr = strings.TrimSpace(expr)
	if semi := strings.Index(expr, ";"); semi != -1 {
		expr = expr[:semi]
	}
	expr = unwrapParens(expr)
	ipCallRe := regexp.MustCompile(`^(?:net\.ParseIP\s*\(.*?\)|[a-zA-Z0-9_]+)\s*\.\s*Is[A-Z]\w*\s*\([^()]*\)$`)
	return ipCallRe.MatchString(expr)
}

func isNegatedIPPredicate(line string) bool {
	cond := strings.TrimSpace(line)
	if strings.HasPrefix(cond, "if ") {
		cond = strings.TrimPrefix(cond, "if ")
	} else if strings.HasPrefix(cond, "if(") {
		cond = strings.TrimPrefix(cond, "if")
	}
	if idx := strings.Index(cond, "{"); idx != -1 {
		cond = cond[:idx]
	}
	cond = strings.TrimSpace(cond)

	// Direct negation check: !ip.IsLoopback(), !(ip.IsLoopback()), (!ip.IsLoopback())
	if strings.Contains(cond, "!") {
		negRe := regexp.MustCompile(`!\s*\(+\s*(?:net\.ParseIP\s*\(.*?\)|[a-zA-Z0-9_]+)\s*\.\s*Is[A-Z]\w*\s*\(|\b!\s*(?:net\.ParseIP\s*\(.*?\)|[a-zA-Z0-9_]+)\s*\.\s*Is[A-Z]\w*\s*\(`)
		if negRe.MatchString(cond) {
			return true
		}
	}

	// Comparison to boolean false: (ip.IsLoopback()) == false or predicate != true
	cmpRe := regexp.MustCompile(`\s*(?:==\s*false|!=\s*true)`)
	for _, loc := range cmpRe.FindAllStringIndex(cond, -1) {
		prefix := strings.TrimSpace(cond[:loc[0]])
		if idx := strings.LastIndexAny(prefix, "&|"); idx != -1 {
			prefix = strings.TrimSpace(prefix[idx+1:])
		}
		prefix = unwrapParens(prefix)
		ipCallRe := regexp.MustCompile(`^(?:net\.ParseIP\s*\(.*?\)|[a-zA-Z0-9_]+)\s*\.\s*Is[A-Z]\w*\s*\([^()]*\)$`)
		if ipCallRe.MatchString(prefix) {
			return true
		}
	}
	return false
}

func isAllowlistContext(line string, lines []string, idx int) bool {
	// 1. Returning the check as a boolean predicate (e.g. return net.ParseIP(...).IsLoopback())
	if isReturnIPPredicate(line) {
		return true
	}

	// 2. Negated check applied directly to the IP predicate:
	// e.g. if !net.ParseIP(u.Hostname()).IsLoopback() or if (ip.IsLoopback()) == false
	// These require the IP property to be true, rejecting non-matching hosts (domain names).
	if isNegatedIPPredicate(line) {
		return true
	}

	// 3. Positive if guard: inspect whether the guarded block accepts AND non-matching path rejects.
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "if ") || strings.HasPrefix(trimmed, "if(") {
		endBlock := findIfBlockEnd(lines, idx)

		branchAccepts := false
		for k := idx; k <= endBlock && k < len(lines); k++ {
			bodyLine := strings.TrimSpace(lines[k])
			if rejectReturnRe.MatchString(bodyLine) {
				return false
			}
			if acceptReturnRe.MatchString(bodyLine) {
				branchAccepts = true
			}
		}

		if branchAccepts {
			// Require evidence that the nonmatching path rejects the hostname,
			// either via an else block that rejects, or fallthrough lines that reject.
			if hasRejectingElse(lines, endBlock) {
				return true
			}
			for k := endBlock + 1; k < len(lines) && k < endBlock+7; k++ {
				ftLine := strings.TrimSpace(lines[k])
				if strings.HasPrefix(ftLine, "func ") {
					break
				}
				if rejectReturnRe.MatchString(ftLine) {
					return true
				}
				if acceptReturnRe.MatchString(ftLine) {
					return false
				}
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
