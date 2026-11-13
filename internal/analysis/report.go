package analysis

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Report is the versioned envelope for analysis results. It is the
// shared output contract: analyzers and semantic frontends emit
// analysis.Report documents; consumers negotiate via SchemaVersion.
//
// Compatibility: this envelope is a NEW document shape. The legacy
// review.Report JSON (schema_version "1.0.0") is unchanged and remains
// the format written to report files today; existing readers continue
// to work. The migration path is review.AnalysisReportFromReview, which
// lifts a legacy Report into this envelope without data loss (legacy
// finding IDs are preserved in Finding.LegacyID).
type Report struct {
	// SchemaVersion is CurrentSchemaVersion for newly written reports.
	SchemaVersion string `json:"schema_version"`

	// RunID optionally correlates the report with a review run.
	RunID string `json:"run_id,omitempty"`
	// GeneratedAt is when the report was assembled (UTC).
	GeneratedAt time.Time `json:"generated_at"`

	// Runs describes each analyzer/frontend execution that contributed
	// results, including the budgets in effect.
	Runs []Run `json:"runs,omitempty"`
	// Findings are the analysis results, deterministically ordered and
	// ID-assigned by NewReport/AssignReport.
	Findings []Finding `json:"findings"`
	// Diagnostics records analysis limitations (load errors, unsupported
	// constructs, truncation) that qualify the findings.
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
}

// NewReport builds a Report with the current schema version, assigned
// finding IDs, and deterministic ordering of findings and diagnostics.
func NewReport(runID string, runs []Run, findings []Finding, diagnostics []Diagnostic) Report {
	findings = AssignFindingIDs(findings)
	SortFindings(findings)
	diagnostics = append([]Diagnostic(nil), diagnostics...)
	SortDiagnostics(diagnostics)
	return Report{
		SchemaVersion: CurrentSchemaVersion,
		RunID:         runID,
		GeneratedAt:   time.Now().UTC(),
		Runs:          runs,
		Findings:      findings,
		Diagnostics:   diagnostics,
	}
}

// Validate checks the report envelope: supported schema version,
// well-formed findings, and well-formed diagnostics.
func (r Report) Validate() error {
	var errs []string
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	if !SupportedSchemaVersions[r.SchemaVersion] {
		add("unsupported schema_version %q", r.SchemaVersion)
	}
	if r.GeneratedAt.IsZero() {
		add("generated_at is required")
	}
	for i, f := range r.Findings {
		if err := f.Validate(); err != nil {
			add("findings[%d]: %v", i, err)
		}
	}
	seen := make(map[string]int, len(r.Findings))
	for i, f := range r.Findings {
		if f.ID == "" {
			add("findings[%d]: id is empty; run AssignFindingIDs before serializing", i)
			continue
		}
		if prev, dup := seen[f.ID]; dup {
			add("findings[%d]: duplicate id %q (also findings[%d])", i, f.ID, prev)
		}
		seen[f.ID] = i
	}
	for i, d := range r.Diagnostics {
		if !d.Severity.Valid() {
			add("diagnostics[%d]: invalid severity %q", i, d.Severity)
		}
		if !d.Category.Valid() {
			add("diagnostics[%d]: invalid category %q", i, d.Category)
		}
		if strings.TrimSpace(d.Message) == "" {
			add("diagnostics[%d]: message is required", i)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid analysis report: %s", strings.Join(errs, "; "))
	}
	return nil
}

// MarshalJSON validates before serializing so an invalid report —
// including one containing a proven finding backed by truncated
// evidence — cannot be written.
func (r Report) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	type plain Report
	return json.Marshal(plain(r))
}

// UnmarshalJSON decodes a report without enforcing validity; callers
// must run Validate (or rely on consumers that do) before trusting
// proven findings. This keeps the reader forward-tolerant: unknown
// additive fields are ignored by encoding/json.
func (r *Report) UnmarshalJSON(data []byte) error {
	type plain Report
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*r = Report(p)
	return nil
}

// WriteJSON serializes the report with indentation, validating first.
func (r Report) WriteJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ReadJSON decodes a report from JSON bytes without validation.
func ReadJSON(data []byte) (Report, error) {
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return Report{}, fmt.Errorf("decode analysis report: %w", err)
	}
	return r, nil
}
