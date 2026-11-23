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
	hostnameAssignRe = regexp.MustCompile(`\b([a-zA-Z0-9_]+)\s*(?::=|=)\s*([a-zA-Z0-9_.]+)\.Hostname\(\)`)
	netParseIPRe     = regexp.MustCompile(`\b([a-zA-Z0-9_]+)\s*(?::=|=)\s*net\.ParseIP\s*\(\s*([^)\n]+)\s*\)`)
	ipNilGuardRe     = regexp.MustCompile(`(?i)(?:==\s*nil|nil\s*==|!\s*[a-zA-Z0-9_]+)`)
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
						if k > i && strings.HasPrefix(strings.TrimSpace(lines[k]), "func ") {
							break
						}
						// Check if nil is safely guarded before or alongside IsLoopback/IsPrivate
						if ipNilRe.MatchString(lines[k]) {
							hasNilGuard = true
						}
						if ipCheckRe.MatchString(lines[k]) {
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
		}
	}
	return findings
}
