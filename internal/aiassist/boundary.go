// Package aiassist enforces authority boundaries separating AI advice from deterministic facts.
package aiassist

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// DisclaimerHeuristic notes that all AI outputs are heuristic and advisory.
	DisclaimerHeuristic = "AI assistance is heuristic and advisory only."

	// DisclaimerAuthority notes that the deterministic engine holds sole verdict authority.
	DisclaimerAuthority = "Deterministic analyzers hold sole authority over findings and quality gates."

	// DisclaimerApproval notes that any proposed code change requires explicit user approval.
	DisclaimerApproval = "All suggested remediations and tests require explicit review before application."
)

// ApplyBoundaryGuards ensures every assistant response adheres to security and authority policies.
func ApplyBoundaryGuards(resp *AssistanceResponse) {
	if resp == nil {
		return
	}

	resp.AuthoritativePolicy = "Deterministic engine holds sole authority over findings and quality gates."

	hasHeuristic := false
	hasAuthority := false
	for _, d := range resp.Disclaimers {
		if strings.Contains(d, "advisory") {
			hasHeuristic = true
		}
		if strings.Contains(d, "authority") {
			hasAuthority = true
		}
	}

	if !hasHeuristic {
		resp.Disclaimers = append(resp.Disclaimers, DisclaimerHeuristic)
	}
	if !hasAuthority {
		resp.Disclaimers = append(resp.Disclaimers, DisclaimerAuthority)
	}

	if resp.Proposal != nil {
		resp.Proposal.RequiresApproval = true
		resp.Proposal.IsAuthoritative = false
		resp.Disclaimers = append(resp.Disclaimers, DisclaimerApproval)
	}

	notice := "Suggested priority is heuristic; deterministic severity remains unchanged."
	for i := range resp.Triage {
		resp.Triage[i].AuthoritativeNotice = notice
	}
}

// ValidateProposalSafety ensures that proposed remediations do not touch forbidden configuration paths.
func ValidateProposalSafety(prop *RemediationProposal, allowedFile string) error {
	if prop == nil {
		return errors.New("proposal is nil")
	}

	if !prop.RequiresApproval {
		return errors.New("proposal must mandate explicit developer approval")
	}

	if prop.IsAuthoritative {
		return errors.New("proposal cannot claim authoritative truth or override deterministic checks")
	}

	patch := prop.DiffPatch
	if strings.Contains(patch, ".git/") || strings.Contains(patch, ".m3tal-review/policy.yaml") {
		return fmt.Errorf("proposal targets protected repository configuration: %s", patch)
	}

	if allowedFile != "" && !strings.Contains(patch, allowedFile) && patch != "" {
		return fmt.Errorf("proposal modifies unexpected file outside scope of finding (%s)", allowedFile)
	}

	return nil
}
