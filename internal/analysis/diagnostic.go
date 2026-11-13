package analysis

import "sort"

// DiagnosticSeverity classifies a Diagnostic. It mirrors the severity
// vocabulary of internal/semantic.Diagnostic so semantic load problems
// map across without translation.
type DiagnosticSeverity string

const (
	// DiagSeverityError: the affected code could not be analyzed.
	DiagSeverityError DiagnosticSeverity = "error"
	// DiagSeverityWarning: partial or degraded analysis.
	DiagSeverityWarning DiagnosticSeverity = "warning"
	// DiagSeverityInfo: a noteworthy limitation or observation.
	DiagSeverityInfo DiagnosticSeverity = "info"
)

// Valid reports whether the severity is recognized.
func (s DiagnosticSeverity) Valid() bool {
	return s == DiagSeverityError || s == DiagSeverityWarning || s == DiagSeverityInfo
}

// DiagnosticCategory classifies why a Diagnostic was produced. The
// values mirror internal/semantic.DiagnosticCategory.
type DiagnosticCategory string

const (
	// DiagLoadError: the package or file could not be loaded.
	DiagLoadError DiagnosticCategory = "load-error"
	// DiagParseError: a source file could not be parsed.
	DiagParseError DiagnosticCategory = "parse-error"
	// DiagTypeError: the package type-checked with errors; analysis may
	// be incomplete.
	DiagTypeError DiagnosticCategory = "type-error"
	// DiagBuildConstraint: files were excluded by build constraints.
	DiagBuildConstraint DiagnosticCategory = "build-constraint"
	// DiagUnsupported: a construct was recognized but not modeled.
	DiagUnsupported DiagnosticCategory = "unsupported"
	// DiagLimit: an analysis bound was reached and results truncated.
	DiagLimit DiagnosticCategory = "limit"
	// DiagNote: general informational note.
	DiagNote DiagnosticCategory = "note"
)

// Valid reports whether the category is recognized.
func (c DiagnosticCategory) Valid() bool {
	switch c {
	case DiagLoadError, DiagParseError, DiagTypeError, DiagBuildConstraint,
		DiagUnsupported, DiagLimit, DiagNote:
		return true
	}
	return false
}

// Diagnostic is a non-fatal analysis problem or observation: load
// failures, parse errors, unsupported constructs, budget exhaustion,
// and similar limitations. Diagnostics are how incomplete analysis is
// surfaced instead of silently dropped; a run with error diagnostics
// must not produce proven findings over the affected targets.
type Diagnostic struct {
	Severity DiagnosticSeverity `json:"severity"`
	Category DiagnosticCategory `json:"category"`
	Message  string             `json:"message"`
	// Span optionally locates the problem in source.
	Span Span `json:"span,omitempty"`
	// Entity optionally references the semantic entity concerned.
	Entity *EntityRef `json:"entity,omitempty"`
}

// SortDiagnostics orders diagnostics deterministically: by span file,
// offset, category, then message.
func SortDiagnostics(ds []Diagnostic) {
	sort.SliceStable(ds, func(i, j int) bool {
		a, b := ds[i], ds[j]
		if a.Span.File != b.Span.File {
			return a.Span.File < b.Span.File
		}
		if a.Span.StartOffset != b.Span.StartOffset {
			return a.Span.StartOffset < b.Span.StartOffset
		}
		if a.Span.StartLine != b.Span.StartLine {
			return a.Span.StartLine < b.Span.StartLine
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.Message < b.Message
	})
}
