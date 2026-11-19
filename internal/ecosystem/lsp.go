// Package ecosystem converts semantic findings into Language Server Protocol (LSP) diagnostics.
package ecosystem

import (
	"fmt"

	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

func mapLSPSeverity(sev string) LSPDiagnosticSeverity {
	switch sev {
	case "critical", "high":
		return LSPSeverityError
	case "medium":
		return LSPSeverityWarning
	case "low":
		return LSPSeverityInformation
	default:
		return LSPSeverityHint
	}
}

// ConvertFindingToLSPDiagnostic translates a model finding into an LSP Diagnostic.
func ConvertFindingToLSPDiagnostic(f model.Finding) LSPDiagnostic {
	line0 := 0
	if f.Line > 0 {
		line0 = f.Line - 1
	}

	diag := LSPDiagnostic{
		Range: LSPRange{
			Start: LSPPosition{Line: line0, Character: 0},
			End:   LSPPosition{Line: line0, Character: 10},
		},
		Severity: mapLSPSeverity(f.Severity),
		Code:     f.Rule,
		Source:   "m3tal-review",
		Message:  f.Message,
	}

	if f.Explanation != nil {
		for _, step := range f.Explanation.EvidenceSteps {
			sLine0 := 0
			diag.RelatedInformation = append(diag.RelatedInformation, LSPRelatedInformation{
				Location: LSPLocation{
					URI: fmt.Sprintf("file://%s", step.Location),
					Range: LSPRange{
						Start: LSPPosition{Line: sLine0, Character: 0},
						End:   LSPPosition{Line: sLine0, Character: 1},
					},
				},
				Message: step.Statement,
			})
		}
	}

	return diag
}
