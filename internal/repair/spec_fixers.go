package repair

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// AgentSpecFixer deterministically remediates agent specification contract
// violations, rewriting optional delegation loopholes into compliant specialist
// delegation requirements.
type AgentSpecFixer struct{}

func (AgentSpecFixer) Name() string {
	return "agent-spec-fixer"
}

func (AgentSpecFixer) CanFix(f review.Finding) bool {
	return f.Rule == "agent-spec-contract" && strings.Contains(f.Message, "Optional delegation")
}

var (
	specOptionalDelegationLineRe = regexp.MustCompile(
		`(?i)^\s*-\s*Delegation\s+is\s+optional\s+support\s+for\s+a\s+standalone\s+audit.*`,
	)
)

func (f AgentSpecFixer) GenerateProposal(ctx context.Context, repoRoot string, finding review.Finding, fileContent []byte) (*Proposal, error) {
	lines := strings.Split(string(fileContent), "\n")
	targetIdx := -1

	if finding.Line > 0 && finding.Line <= len(lines) {
		idx := finding.Line - 1
		if specOptionalDelegationLineRe.MatchString(lines[idx]) || strings.Contains(lines[idx], "Delegation is optional") {
			targetIdx = idx
		}
	}

	if targetIdx == -1 {
		for i, line := range lines {
			if specOptionalDelegationLineRe.MatchString(line) || strings.Contains(line, "Delegation is optional") {
				targetIdx = i
				break
			}
		}
	}

	if targetIdx == -1 {
		return nil, fmt.Errorf("could not locate optional delegation line in %s", finding.File)
	}

	compliantLine := "- When delegation is available, consult and delegate to the relevant specialists as required by AGENTS.md. If delegation is unavailable, perform the review directly, disclose the limitation, and apply the Partial coverage rule above."
	lines[targetIdx] = compliantLine

	proposed := strings.Join(lines, "\n")
	return NewProposal(
		"",
		finding,
		f.Name(),
		finding.File,
		string(fileContent),
		proposed,
		"Remediated optional delegation loophole to require domain specialist delegation when available.",
	), nil
}
