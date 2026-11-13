// Package analysis defines the shared analysis-result contract used by
// m3tal-review analyzers and semantic frontends.
//
// The contract makes findings explainable, comparable, reproducible, and
// honest about what was actually established:
//
//   - A Finding carries stable source spans, an ordered evidence trace
//     (source-to-sink paths, call chains, control-flow paths, state
//     transitions, lock sequences), assumptions, and truncation/budget
//     information.
//   - A Status distinguishes proven violations, potential violations, and
//     unverified properties. Incomplete analysis can never be serialized
//     as proven: Finding.MarshalJSON refuses to emit a proven finding
//     whose evidence is truncated or absent.
//   - Finding IDs are derived deterministically from the rule ID, primary
//     span, and evidence-step identities, so repeat runs over unchanged
//     evidence produce identical identifiers.
//   - A Report envelope versions the schema (CurrentSchemaVersion) so
//     consumers can negotiate compatibility.
//
// Relationship to the existing review report format:
//
// The legacy report (internal/review.Report) keeps its schema_version
// "1.0.0" JSON shape unchanged; existing readers are unaffected. This
// package is additive: analyzers and frontends may emit analysis.Report
// documents alongside (or instead of) legacy reports, and
// review.AnalysisReportFromReview / review.AnalysisFindingFromReview in
// internal/review/analysis_adapter.go convert legacy findings into the
// shared contract as the migration path. Legacy findings never carry
// proof traces, so the adapter conservatively marks them StatusPotential
// (or StatusUnverified when truncation is declared).
//
// Confidence vocabulary: analysis.Confidence uses the lowercase
// normalized values produced by review.NormalizeConfidence
// ("high"/"medium"/"low", plus "unknown"). It is unrelated to
// internal/review/language.Confidence, which is capitalized
// ("High"/"Medium"/"Low") and measures *language-detection* certainty,
// not finding confidence. The two types must not be conflated; convert
// through ParseConfidence when bridging.
package analysis

import "time"

// CurrentSchemaVersion is the schema version written into every
// analysis.Report produced by this package. Bump it on any
// backwards-incompatible change to the JSON shape; additive omitempty
// fields do not require a bump.
const CurrentSchemaVersion = "analysis/1.0.0"

// SupportedSchemaVersions lists schema versions this package can read.
// The empty string is accepted for forward-tolerant handling of reports
// written before versioning was enforced.
var SupportedSchemaVersions = map[string]bool{
	"":                   true,
	"analysis/1":         true,
	CurrentSchemaVersion: true,
}

// Run describes a single analyzer or frontend execution that contributed
// findings and diagnostics to a Report.
type Run struct {
	// ID is an opaque run identifier (e.g. the review run ID). It is not
	// part of finding identity.
	ID string `json:"id,omitempty"`
	// Analyzer names the rule or analyzer that produced the results
	// (e.g. "taint", "sqli"). Empty for whole-program frontend runs.
	Analyzer string `json:"analyzer,omitempty"`
	// ToolName and ToolVersion identify the emitting tool.
	ToolName      string `json:"tool_name,omitempty"`
	ToolVersion   string `json:"tool_version,omitempty"`
	SchemaVersion string `json:"schema_version,omitempty"`
	// Targets are the files, packages, or revisions the run covered.
	Targets []string `json:"targets,omitempty"`
	// Budgets are the path/iteration/resource limits in effect for the
	// run. A budget with Truncated=true means the run hit that limit.
	Budgets []Budget `json:"budgets,omitempty"`
	// StartedAt and FinishedAt bound the run; nil means unknown.
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}
