package review

import (
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
)

// This file adapts the legacy review report format (model.Finding /
// Report, schema_version "1.0.0") to the shared analysis contract
// (internal/analysis). It is the migration path described in issue #133:
// built-in analyzers keep emitting legacy findings, and callers that
// want the shared contract convert at the boundary.
//
// Mapping notes:
//   - Legacy findings carry no proof traces, so they are conservatively
//     emitted as StatusPotential. An analyzer may declare a different
//     status via the metadata key "analysis_status" ("proven",
//     "potential", or "unverified"); proven is still subject to
//     analysis.Finding.Validate, so a truncated or evidence-free
//     "proven" claim fails loudly at serialization time.
//   - Truncation declared via metadata key "analysis_truncated"="true"
//     (or "analysis_truncation_reasons"="a;b") is carried into
//     Truncation, which downgrades any proven claim.
//   - Confidence passes through analysis.ParseConfidence, which mirrors
//     review.NormalizeConfidence's vocabulary.
//   - The legacy finding ID is preserved in Finding.LegacyID; the new
//     deterministic ID is derived from rule + span + evidence.
//   - File/Line become a single-line Span; FindingEvidence entries
//     become EvidenceNote steps carrying their message and line.

const (
	metaAnalysisStatus    = "analysis_status"
	metaAnalysisTruncated = "analysis_truncated"
	metaTruncationReasons = "analysis_truncation_reasons"
)

// AnalysisFindingFromReview converts a legacy finding into the shared
// analysis contract.
func AnalysisFindingFromReview(f Finding) analysis.Finding {
	out := analysis.Finding{
		RuleID:      firstNonEmpty(f.Rule, joinRules(f.Rules)),
		RuleName:    f.Rule,
		Message:     f.Message,
		Category:    f.Category,
		Severity:    strings.ToLower(strings.TrimSpace(f.Severity)),
		Confidence:  analysis.ParseConfidence(f.Confidence),
		Status:      analysis.StatusPotential,
		Trace:       analysis.TraceGeneral,
		Spans:       reviewSpans(f),
		Evidence:    reviewEvidenceSteps(f),
		Remediation: f.Remediation,
		LegacyID:    f.ID,
		Metadata:    copyStringMap(f.Metadata),
	}

	// Optional analyzer-declared status override.
	if s, ok := analysis.ParseStatus(f.Metadata[metaAnalysisStatus]); ok {
		out.Status = s
	}

	// Optional truncation declaration.
	if isTruthy(f.Metadata[metaAnalysisTruncated]) {
		out.Truncation.Truncated = true
	}
	if reasons := f.Metadata[metaTruncationReasons]; reasons != "" {
		for _, r := range strings.Split(reasons, ";") {
			if r = strings.TrimSpace(r); r != "" {
				out.Truncation.Reasons = append(out.Truncation.Reasons, r)
			}
		}
	}
	if out.Truncation.Truncated || len(out.Truncation.Reasons) > 0 {
		// Incomplete analysis can never be proven; downgrade loudly at
		// the boundary rather than letting Validate reject later.
		if out.Status == analysis.StatusProven {
			out.Status = analysis.StatusPotential
		}
	}

	return out.EnsureID()
}

// AnalysisFindingsFromReview converts a slice of legacy findings,
// assigning deterministic analysis IDs and resolving collisions.
func AnalysisFindingsFromReview(findings []Finding) []analysis.Finding {
	out := make([]analysis.Finding, 0, len(findings))
	for _, f := range findings {
		out = append(out, AnalysisFindingFromReview(f))
	}
	return analysis.AssignFindingIDs(out)
}

// AnalysisReportFromReview lifts a legacy review.Report into the shared
// analysis envelope. The legacy report is not modified; run metadata is
// captured as a single analysis.Run describing the review execution.
func AnalysisReportFromReview(r Report) analysis.Report {
	run := analysis.Run{
		ID:            r.RunID,
		Analyzer:      "m3tal-review",
		ToolVersion:   r.ToolVersion,
		SchemaVersion: r.SchemaVersion,
		Targets:       append([]string(nil), r.ReviewedFiles...),
	}
	if !r.Timestamp.IsZero() {
		ts := r.Timestamp.UTC()
		run.StartedAt = &ts
		run.FinishedAt = &ts
	}

	diagnostics := make([]analysis.Diagnostic, 0, len(r.UnanalyzedFiles))
	for _, f := range r.UnanalyzedFiles {
		diagnostics = append(diagnostics, analysis.Diagnostic{
			Severity: analysis.DiagSeverityWarning,
			Category: analysis.DiagUnsupported,
			Message:  "file was not analyzed: " + f,
			Span:     analysis.Span{File: f},
		})
	}

	return analysis.NewReport(r.RunID, []analysis.Run{run},
		AnalysisFindingsFromReview(r.Findings), diagnostics)
}

// reviewSpans maps the legacy File/Line location onto analysis spans.
func reviewSpans(f Finding) []analysis.Span {
	if strings.TrimSpace(f.File) == "" {
		return nil
	}
	line := f.Line
	if line < 1 {
		line = 1
	}
	return []analysis.Span{{
		File:      f.File,
		StartLine: line,
		EndLine:   line,
		Snippet:   f.Snippet,
	}}
}

// reviewEvidenceSteps maps legacy FindingEvidence records onto ordered
// note steps located at the finding's file (and the evidence line when
// present). Legacy evidence carries no structural kind, so all steps
// are EvidenceNote; richer analyzers should emit analysis.Finding
// directly.
func reviewEvidenceSteps(f Finding) []analysis.EvidenceStep {
	if len(f.Evidence) == 0 {
		return nil
	}
	steps := make([]analysis.EvidenceStep, 0, len(f.Evidence))
	for _, ev := range f.Evidence {
		step := analysis.EvidenceStep{
			Kind: analysis.EvidenceNote,
			Note: ev.Message,
		}
		if ev.Rule != "" || ev.Analyzer != "" {
			var parts []string
			if ev.Analyzer != "" {
				parts = append(parts, "analyzer="+ev.Analyzer)
			}
			if ev.Rule != "" {
				parts = append(parts, "rule="+ev.Rule)
			}
			if step.Note != "" {
				step.Note += " (" + strings.Join(parts, ", ") + ")"
			} else {
				step.Note = strings.Join(parts, ", ")
			}
		}
		line := ev.Line
		if line < 1 {
			line = f.Line
		}
		if line > 0 {
			step.Span = analysis.SingleLineSpan(f.File, line)
		}
		steps = append(steps, step)
	}
	return steps
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func joinRules(rules []string) string {
	return strings.Join(rules, ",")
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
