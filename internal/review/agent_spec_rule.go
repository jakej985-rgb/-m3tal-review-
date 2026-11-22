package review

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

// AgentSpecRule performs deterministic semantic contract verification on AI agent
// instructions and governance specifications (.agents/agents/*/agent.md, AGENTS.md),
// detecting cross-spec policy contradictions, configuration mismatches, and
// directive scope collisions without external LLMs.
type AgentSpecRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (AgentSpecRule) Name() string {
	return "agent-spec-contract"
}

func (r AgentSpecRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	// Delegation policy patterns
	optionalDelegationRe = regexp.MustCompile(
		`(?i)\b(?:delegation\s+is\s+optional(?:\s+support)?|optional\s+support\s+for\s+a\s+standalone\s+audit|delegation\s+is\s+not\s+(?:a\s+)?prerequisite)\b`,
	)
	mandatedDelegationCheckRe = regexp.MustCompile(
		`(?i)\b(?:when\s+delegation\s+is\s+available,\s+consult\s+and\s+delegate|must\s+delegate\s+to\s+specialists)\b`,
	)

	// Scope collision patterns
	narrowestModeRe = regexp.MustCompile(
		`(?i)\b(?:narrowest\s+mode|choose\s+the\s+narrowest\s+mode|narrowest-mode\s+rule)\b`,
	)
	fullAuditMandateRe = regexp.MustCompile(
		`(?i)\b(?:must\s+still\s+perform\s+its\s+full\s+repository\s+audit|standalone\s+does\s+not\s+mean\s+reduced\s+scope|full-audit\s+mandate)\b`,
	)
	precedenceClauseRe = regexp.MustCompile(
		`(?i)\b(?:takes\s+precedence|unless|precedence\s+over|except\s+when|narrowest\s+mode\s+supersedes)\b`,
	)

	// Direct invocation vs subagent config patterns
	directInvocationProseRe = regexp.MustCompile(
		`(?i)\b(?:when\s+(?:\w+\s+)?is\s+invoked\s+directly|standalone\s+invocation\s+contract|standalone\s+does\s+not\s+mean\s+reduced\s+scope)\b`,
	)
	subagentConfigRe = regexp.MustCompile(
		`(?m)^mainAgent:\s*false\b`,
	)
)

func isAgentSpecFile(path string) bool {
	lower := strings.ToLower(path)
	if !strings.HasSuffix(lower, ".md") && !strings.HasSuffix(lower, ".markdown") {
		return false
	}
	return strings.Contains(lower, "agent") || strings.Contains(lower, "agents/")
}

func (r AgentSpecRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if !isAgentSpecFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		// Read entire file if accessible for full context (frontmatter, cross-sections)
		fullContent := ""
		if r.RepositoryRoot != "" {
			fullPath := filepath.Join(r.RepositoryRoot, filePath)
			if data, err := os.ReadFile(fullPath); err == nil {
				fullContent = string(data)
			}
		}
		if fullContent == "" && len(blocks) > 0 {
			fullContent = blocks[0].text
		}

		isConfiguredAsSubagent := subagentConfigRe.MatchString(fullContent)
		hasNarrowestModeDirective := narrowestModeRe.MatchString(fullContent)

		for _, block := range blocks {
			lines := strings.Split(block.text, "\n")
			for i, line := range lines {
				lineNum := block.firstLine + i

				if !block.addedLines[lineNum] && len(block.addedLines) > 0 {
					continue
				}

				// Check 1: Optional delegation bypasses required domain specialists
				if optionalDelegationRe.MatchString(line) && !mandatedDelegationCheckRe.MatchString(line) {
					key := fmt.Sprintf("%s:%d:delegation", filePath, lineNum)
						if !seen[key] {
							seen[key] = true
							findings = append(findings, Finding{
								Rule:        "agent-spec-contract",
								Severity:    "high",
								Category:    "drift",
								Confidence:  "High",
								File:        filePath,
								Line:        lineNum,
								Message:     "Optional delegation bypasses required domain specialists declared in AGENTS.md",
								Remediation: "When delegation is available, consult and delegate to the relevant specialists as required by AGENTS.md. If delegation is unavailable, perform the review directly, disclose the limitation, and apply the Partial coverage rule above.",
								Explanation: &model.FindingExplanation{
									RuleRationale:   "Repository governance requires delegating domain-specific verification to specialized agents. Subagents must not silently bypass specialist review.",
									EvidenceSummary: "Line declares delegation as optional without conditioning on unavailability.",
									EvidenceKind:    "contract-inconsistency",
								},
							})
						}
				}

				// Check 2: Unclear scope for direct requests (Scope collision without precedence)
				if fullAuditMandateRe.MatchString(line) && hasNarrowestModeDirective {
					if !precedenceClauseRe.MatchString(line) && !precedenceClauseRe.MatchString(block.text) {
						key := fmt.Sprintf("%s:%d:scope-collision", filePath, lineNum)
						if !seen[key] {
							seen[key] = true
							findings = append(findings, Finding{
								Rule:        "agent-spec-contract",
								Severity:    "medium",
								Category:    "drift",
								Confidence:  "High",
								File:        filePath,
								Line:        lineNum,
								Message:     "Unclear scope for direct requests: direct full-audit mandate conflicts with the narrowest-mode rule without explicit precedence",
								Remediation: "Clarify precedence: specify whether targeted requests (such as issue reconciliation or planning) take precedence over the full-audit mandate.",
								Explanation: &model.FindingExplanation{
									RuleRationale:   "Agent specifications defining multiple conflicting scope rules must define explicit precedence to avoid unpredictable agent execution.",
									EvidenceSummary: "Direct full-audit mandate added to specification that already contains a narrowest-mode rule without precedence.",
									EvidenceKind:    "contract-inconsistency",
								},
							})
						}
					}
				}

				// Check 3: Unverified direct invocation path (Config vs Prose Invariant)
				if isConfiguredAsSubagent && directInvocationProseRe.MatchString(line) {
					key := fmt.Sprintf("%s:%d:direct-invocation", filePath, lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "agent-spec-contract",
							Severity:    "medium",
							Category:    "drift",
							Confidence:  "High",
							File:        filePath,
							Line:        lineNum,
							Message:     "Unverified direct invocation path: agent is configured as a subagent (mainAgent: false) but instructions define direct/standalone invocation",
							Remediation: "Verify direct invocation path: set mainAgent: true in frontmatter if direct user invocation is intended, or clarify the host dispatch routing.",
							Explanation: &model.FindingExplanation{
								RuleRationale:   "Agent frontmatter metadata defines host execution permissions; subagent-only configurations cannot be directly invoked as primary agents.",
								EvidenceSummary: "Direct standalone contract defined in an agent whose frontmatter specifies mainAgent: false.",
								EvidenceKind:    "config-inconsistency",
							},
						})
					}
				}
			}
		}
	}

	return findings
}

func (r AgentSpecRule) loadRootAgentsMD() string {
	candidates := []string{
		"AGENTS.md",
		".agents/AGENTS.md",
		"agents.md",
		"docs/AGENTS.md",
	}

	for _, cand := range candidates {
		var path string
		if r.RepositoryRoot != "" {
			path = filepath.Join(r.RepositoryRoot, cand)
		} else {
			path = cand
		}
		if data, err := os.ReadFile(path); err == nil {
			return string(data)
		}
	}
	return ""
}
