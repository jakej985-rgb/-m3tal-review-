// Package ecosystem provides developer workflow, CI/CD, and IDE integrations.
package ecosystem

import (
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

// LSPDiagnosticSeverity corresponds to LSP DiagnosticSeverity levels.
type LSPDiagnosticSeverity int

const (
	LSPSeverityError       LSPDiagnosticSeverity = 1
	LSPSeverityWarning     LSPDiagnosticSeverity = 2
	LSPSeverityInformation LSPDiagnosticSeverity = 3
	LSPSeverityHint        LSPDiagnosticSeverity = 4
)

// LSPPosition represents a 0-based position in a text document.
type LSPPosition struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

// LSPRange represents a range in a text document.
type LSPRange struct {
	Start LSPPosition `json:"start"`
	End   LSPPosition `json:"end"`
}

// LSPLocation links to a specific range in a file.
type LSPLocation struct {
	URI   string   `json:"uri"`
	Range LSPRange `json:"range"`
}

// LSPRelatedInformation provides evidence references in an LSP diagnostic.
type LSPRelatedInformation struct {
	Location LSPLocation `json:"location"`
	Message  string      `json:"message"`
}

// LSPDiagnostic represents a Language Server Protocol diagnostic item.
type LSPDiagnostic struct {
	Range              LSPRange                `json:"range"`
	Severity           LSPDiagnosticSeverity   `json:"severity"`
	Code               string                  `json:"code"`
	Source             string                  `json:"source"`
	Message            string                  `json:"message"`
	RelatedInformation []LSPRelatedInformation `json:"relatedInformation,omitempty"`
}

// ExternalToolResult describes output from an external analyzer.
type ExternalToolResult struct {
	ToolName    string        `json:"tool_name"`
	ExitCode    int           `json:"exit_code"`
	Failed      bool          `json:"failed"`
	ErrorOutput string        `json:"error_output,omitempty"`
	RawFindings []byte        `json:"raw_findings,omitempty"`
	Duration    time.Duration `json:"duration"`
}

// Normalizer converts external tool output to internal model findings.
type Normalizer interface {
	Name() string
	Normalize(res ExternalToolResult) ([]model.Finding, error)
}
