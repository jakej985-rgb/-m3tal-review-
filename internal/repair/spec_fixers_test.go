package repair

import (
	"context"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestAgentSpecFixer_RewritesOptionalDelegation(t *testing.T) {
	content := `### Standalone invocation contract

When M3tal Scout is invoked directly, perform full audit.

- There is no limit on findings.
- Delegation is optional support for a standalone audit, not a prerequisite for Scout's core full-audit capability. If delegation is unavailable, perform the review directly and disclose that limitation.
`

	finding := review.Finding{
		Rule:    "agent-spec-contract",
		File:    ".agents/agents/m3tal-scout/agent.md",
		Line:    6,
		Message: "Optional delegation bypasses required domain specialists declared in AGENTS.md",
	}

	fixer := AgentSpecFixer{}
	if !fixer.CanFix(finding) {
		t.Fatal("expected fixer.CanFix(finding) to be true")
	}

	prop, err := fixer.GenerateProposal(context.Background(), "", finding, []byte(content))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedSnippet := "- When delegation is available, consult and delegate to the relevant specialists as required by AGENTS.md. If delegation is unavailable, perform the review directly, disclose the limitation, and apply the Partial coverage rule above."
	if !strings.Contains(prop.ProposedContent, expectedSnippet) {
		t.Fatalf("expected compliant snippet in proposed content, got:\n%s", prop.ProposedContent)
	}
	if strings.Contains(prop.ProposedContent, "Delegation is optional") {
		t.Fatalf("did not expect 'Delegation is optional' in proposed content, got:\n%s", prop.ProposedContent)
	}
}
