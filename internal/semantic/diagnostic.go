package semantic

// Severity classifies a Diagnostic.
type Severity string

const (
	// SeverityError indicates the affected code could not be analyzed.
	SeverityError Severity = "error"
	// SeverityWarning indicates partial or degraded analysis.
	SeverityWarning Severity = "warning"
	// SeverityInfo records a noteworthy limitation or observation.
	SeverityInfo Severity = "info"
)

// DiagnosticCategory classifies why a Diagnostic was produced.
type DiagnosticCategory string

const (
	// DiagLoadError: the package or file could not be loaded at all
	// (missing files, go list failure, driver errors).
	DiagLoadError DiagnosticCategory = "load-error"
	// DiagParseError: a source file could not be parsed.
	DiagParseError DiagnosticCategory = "parse-error"
	// DiagTypeError: the package type-checked with errors; analysis of
	// it may be incomplete.
	DiagTypeError DiagnosticCategory = "type-error"
	// DiagBuildConstraint: files were excluded by build constraints;
	// the modeled package may differ from other build configurations.
	DiagBuildConstraint DiagnosticCategory = "build-constraint"
	// DiagUnsupported: a construct was recognized but not modeled.
	DiagUnsupported DiagnosticCategory = "unsupported"
	// DiagLimit: an analysis bound was reached and results were
	// truncated.
	DiagLimit DiagnosticCategory = "limit"
	// DiagNote: general informational note.
	DiagNote DiagnosticCategory = "note"
)

// Diagnostic is a non-fatal analysis problem or observation. The
// frontend guarantees that every load/parse/type failure it encounters
// is recorded here rather than silently dropped.
type Diagnostic struct {
	Severity Severity
	Category DiagnosticCategory
	Message  string
	// Package is the import path the diagnostic pertains to, if any.
	Package string
	Position
}
