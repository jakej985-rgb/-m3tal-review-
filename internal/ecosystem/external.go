// Package ecosystem normalizes external analyzer outputs with strict failure semantics.
package ecosystem

import (
	"encoding/json"
	"fmt"

	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

// ExternalToolError signals an explicit failure of a required external analyzer.
type ExternalToolError struct {
	ToolName string
	ExitCode int
	Details  string
}

func (e *ExternalToolError) Error() string {
	return fmt.Sprintf("external analyzer %s failed with exit code %d: %s",
		e.ToolName, e.ExitCode, e.Details)
}

// GenericRawFinding models standard JSON finding schemas from external CLI linters.
type GenericRawFinding struct {
	RuleID   string `json:"rule_id"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// GenericNormalizer normalizes generic JSON findings into model.Finding records.
type GenericNormalizer struct {
	ProviderName string
}

// Name returns the normalizer identifier.
func (n *GenericNormalizer) Name() string {
	if n.ProviderName != "" {
		return n.ProviderName
	}
	return "generic-linter"
}

// Normalize parses external tool findings and converts them to internal model findings.
func (n *GenericNormalizer) Normalize(res ExternalToolResult) ([]model.Finding, error) {
	if res.Failed || res.ExitCode != 0 {
		return nil, &ExternalToolError{
			ToolName: res.ToolName,
			ExitCode: res.ExitCode,
			Details:  res.ErrorOutput,
		}
	}

	if len(res.RawFindings) == 0 {
		return nil, nil
	}

	var rawList []GenericRawFinding
	if err := json.Unmarshal(res.RawFindings, &rawList); err != nil {
		return nil, fmt.Errorf("failed to parse %s output: %w", res.ToolName, err)
	}

	var findings []model.Finding
	for _, rf := range rawList {
		sev := rf.Severity
		if sev == "" {
			sev = "medium"
		}

		findingID := fmt.Sprintf("%s:%s:%d", res.ToolName, rf.File, rf.Line)
		ruleName := fmt.Sprintf("%s/%s", res.ToolName, rf.RuleID)
		findings = append(findings, model.Finding{
			ID:          findingID,
			Rule:        ruleName,
			Severity:    sev,
			Category:    "external",
			File:        rf.File,
			Line:        rf.Line,
			Message:     rf.Message,
			Confidence:  "high",
		})
	}

	return findings, nil
}
