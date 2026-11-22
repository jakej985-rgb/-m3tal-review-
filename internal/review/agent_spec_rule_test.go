package review

import (
	"strings"
	"testing"
)

func TestAgentSpecRule_CatchesPR68Contradictions(t *testing.T) {
	src := `---
name: m3tal-scout
description: Whole-repository engineering auditor
mainAgent: false
subagent: true
---

## Operating modes

Choose the narrowest mode that fulfills the user's request. Modes do not grant write permission.

## Audit strategy: full coverage, multiple passes

### Standalone invocation contract

When M3tal Scout is invoked directly (not by an orchestrator), it must still perform its full repository audit. **Standalone does not mean reduced scope.**

- There is **no limit on the number of valid findings** Scout may report.
- Do not stop after finding one issue, after an initial scan, or after one subsystem.
- Continue through all applicable audit domains and subsystems in the coverage matrix.
- Report multiple findings when supported by evidence; split independently actionable root causes.
- If time, context, repository size, tool access, or delegation limits prevent full coverage, clearly mark the audit **Partial**.
- Delegation is optional support for a standalone audit, not a prerequisite for Scout's core full-audit capability. If delegation is unavailable, perform the review directly and disclose that limitation.
`
	diff := goDiff(".agents/agents/m3tal-scout/agent.md", src)

	rule := AgentSpecRule{}
	findings := rule.Check(diff)

	if len(findings) < 3 {
		t.Fatalf("expected at least 3 findings for PR 68, got %d: %+v", len(findings), findings)
	}

	var hasDelegation, hasScopeCollision, hasDirectInvocation bool
	for _, f := range findings {
		if f.Rule != "agent-spec-contract" {
			t.Errorf("unexpected rule %s", f.Rule)
		}
		if strings.Contains(f.Message, "Optional delegation") {
			hasDelegation = true
		}
		if strings.Contains(f.Message, "Unclear scope for direct requests") {
			hasScopeCollision = true
		}
		if strings.Contains(f.Message, "Unverified direct invocation path") {
			hasDirectInvocation = true
		}
	}

	if !hasDelegation {
		t.Errorf("missing Optional delegation finding; findings: %+v", findings)
	}
	if !hasScopeCollision {
		t.Errorf("missing Unclear scope finding; findings: %+v", findings)
	}
	if !hasDirectInvocation {
		t.Errorf("missing Unverified direct invocation finding; findings: %+v", findings)
	}
}

func TestAgentSpecRule_AllowsCompliantDelegation(t *testing.T) {
	diff := `diff --git a/.agents/agents/m3tal-scout/agent.md b/.agents/agents/m3tal-scout/agent.md
index 4fb47d3..aa03b33 100644
--- a/.agents/agents/m3tal-scout/agent.md
+++ b/.agents/agents/m3tal-scout/agent.md
@@ -1,15 +1,15 @@
 ---
 name: m3tal-scout
 description: Whole-repository engineering auditor
-mainAgent: true
+mainAgent: true
 subagent: false
 ---
 
 ## Audit strategy: full coverage, multiple passes
 
+- When delegation is available, consult and delegate to the relevant specialists as required by AGENTS.md. If delegation is unavailable, perform the review directly, disclose the limitation, and apply the Partial coverage rule above.
`

	rule := AgentSpecRule{}
	findings := rule.Check(diff)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for compliant spec, got %d: %+v", len(findings), findings)
	}
}
