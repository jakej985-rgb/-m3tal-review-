package crosslanguage

import (
	"context"

	"github.com/jakej985-rgb/m3tal-review/internal/analyzers"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/repo"
	"github.com/jakej985-rgb/m3tal-review/internal/planning"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
	"github.com/jakej985-rgb/m3tal-review/protocol"
)

// SecurityAnalyzer runs cross-language secrets and credential checks.
type SecurityAnalyzer struct{}

func (SecurityAnalyzer) Metadata() planning.AnalyzerMetadata {
	return planning.AnalyzerMetadata{
		ID: "cross-security", Name: "Cross-language security", Kind: planning.KindCrossLanguage,
		Profiles:     []string{"fast", "security", "full"},
		Capabilities: []string{"secrets", "injection"},
		Description:  "Secrets, credentials, and cross-language security patterns",
	}
}

func (SecurityAnalyzer) Analyze(_ context.Context, req analyzers.Request) (analyzers.Result, error) {
	pFiles := make([]protocol.File, 0, len(req.Files))
	for _, f := range req.Files {
		pFiles = append(pFiles, protocol.File{Path: f.Path, Status: "modified", Content: f.Content})
	}
	out := (repo.App{}).Run(protocol.Input{Protocol: protocol.Version, Files: pFiles})
	findings := make([]review.Finding, 0, len(out.Findings))
	for _, f := range out.Findings {
		findings = append(findings, review.Finding{
			Rule: f.Rule, Category: f.Category, Severity: f.Severity, Confidence: f.Confidence,
			File: f.File, Line: f.Line, Message: f.Message, Remediation: f.Remediation, Snippet: f.Evidence,
		})
	}
	return analyzers.Result{AnalyzerID: "cross-security", Findings: findings}, nil
}

// RegisterAll registers all cross-language analyzers.
func RegisterAll(reg *analyzers.Registry) {
	reg.Register(SecurityAnalyzer{})
}
