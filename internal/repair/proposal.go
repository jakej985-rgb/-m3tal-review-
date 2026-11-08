package repair

import (
	"fmt"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// Proposal represents a concrete, proposed automated remediation for an eligible finding.
type Proposal struct {
	ID              string         `json:"id"`
	Finding         review.Finding `json:"finding"`
	FixerName       string         `json:"fixer_name"`
	TargetFile      string         `json:"target_file"`
	OriginalContent string         `json:"original_content"`
	ProposedContent string         `json:"proposed_content"`
	Patch           string         `json:"patch"`
	Explanation     string         `json:"explanation"`
	CreatedAt       time.Time      `json:"created_at"`
}

// NewProposal constructs a Proposal and automatically computes its unified diff patch.
func NewProposal(id string, finding review.Finding, fixerName, targetFile, originalContent, proposedContent, explanation string) *Proposal {
	if id == "" {
		id = fmt.Sprintf("prop-%d", time.Now().UnixNano())
	}
	patch := GenerateUnifiedDiff(targetFile, originalContent, proposedContent)
	return &Proposal{
		ID:              id,
		Finding:         finding,
		FixerName:       fixerName,
		TargetFile:      targetFile,
		OriginalContent: originalContent,
		ProposedContent: proposedContent,
		Patch:           patch,
		Explanation:     explanation,
		CreatedAt:       time.Now().UTC(),
	}
}
