package review

import (
	"path/filepath"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
)

// This file is the reverse direction of analysis_adapter.go: it
// converts findings produced by the semantic pipeline
// (internal/analysis/pipeline, shared analysis.Finding contract) into
// the legacy review.Finding shape consumed by the existing report,
// filters, formats, and history.
//
// Mapping notes:
//   - Category is "semantic" so report consumers can separate
//     semantic-engine findings from the low-cost pattern tier.
//   - The analysis finding ID (16 hex chars, evidence-derived) is
//     preserved; review.AssignFindingIDs keeps unique IDs.
//   - The epistemic status and truncation are carried through
//     Metadata (analysis_status / analysis_truncated /
//     analysis_truncation_reasons) — the same keys the forward
//     adapter honors — plus analysis_trace.
//   - Evidence steps become FindingEvidence entries with the analyzer
//     name, line, and note text; structural kinds are prefixed into
//     the message so no information is lost.
//   - Absolute source paths from the semantic frontend are relativized
//     to the repository root when possible.

// ReviewFindingFromAnalysis converts one shared-contract finding into
// the legacy report shape. repoRoot is used to relativize span files;
// pass "" to keep paths as recorded.
func ReviewFindingFromAnalysis(f analysis.Finding, repoRoot string) Finding {
	out := Finding{
		ID:          f.ID,
		Category:    "semantic",
		Rule:        firstNonEmpty(f.RuleID, f.RuleName),
		Severity:    strings.ToLower(strings.TrimSpace(f.Severity)),
		Confidence:  string(f.Confidence),
		Message:     f.Message,
		Remediation: f.Remediation,
		Metadata:    copyStringMap(f.Metadata),
	}
	if out.Severity == "" {
		out.Severity = "medium"
	}
	if f.Analyzer != "" {
		out.Analyzers = []string{f.Analyzer}
	}
	if out.Rule == "" {
		out.Rule = "semantic-finding"
	}

	// Location: primary span.
	span := f.PrimarySpan()
	out.File = relativizeSpanFile(span.File, repoRoot)
	line := span.StartLine
	if line <= 0 {
		line = span.EndLine
	}
	out.Line = line
	out.Snippet = span.Snippet

	// Evidence trace -> legacy evidence entries.
	if len(f.Evidence) > 0 {
		out.Evidence = make([]FindingEvidence, 0, len(f.Evidence))
		for _, step := range f.Evidence {
			ev := FindingEvidence{
				Analyzer: f.Analyzer,
				Rule:     f.RuleID,
				Message:  evidenceStepMessage(step),
			}
			if step.Span.StartLine > 0 {
				ev.Line = step.Span.StartLine
			}
			out.Evidence = append(out.Evidence, ev)
		}
	}

	// Analysis contract annotations -> metadata keys honored by the
	// forward adapter and useful to report consumers.
	if out.Metadata == nil {
		out.Metadata = make(map[string]string)
	}
	if f.Status != "" {
		out.Metadata[metaAnalysisStatus] = string(f.Status)
	}
	if f.Trace != "" {
		out.Metadata["analysis_trace"] = string(f.Trace)
	}
	if !f.Truncation.Complete() {
		out.Metadata[metaAnalysisTruncated] = "true"
		if len(f.Truncation.Reasons) > 0 {
			out.Metadata[metaTruncationReasons] = strings.Join(f.Truncation.Reasons, ";")
		}
	}
	for _, a := range f.Assumptions {
		if out.Metadata["analysis_assumptions"] == "" {
			out.Metadata["analysis_assumptions"] = a
		} else {
			out.Metadata["analysis_assumptions"] += ";" + a
		}
	}
	return out
}

// ReviewFindingsFromAnalysis converts a slice of shared-contract
// findings, preserving their deterministic IDs.
func ReviewFindingsFromAnalysis(findings []analysis.Finding, repoRoot string) []Finding {
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		out = append(out, ReviewFindingFromAnalysis(f, repoRoot))
	}
	return out
}

// relativizeSpanFile converts an absolute frontend path into a
// repository-relative slash path. Non-absolute or outside-repo paths
// are returned unchanged (slash-normalized).
func relativizeSpanFile(file, repoRoot string) string {
	if file == "" {
		return ""
	}
	file = filepath.ToSlash(file)
	if repoRoot == "" {
		return file
	}
	root := filepath.ToSlash(filepath.Clean(repoRoot))
	if rel, err := filepath.Rel(root, file); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
		return filepath.ToSlash(rel)
	}
	return file
}

// evidenceStepMessage renders an evidence step for the legacy
// FindingEvidence.Message field, keeping the structural kind visible.
func evidenceStepMessage(step analysis.EvidenceStep) string {
	kind := string(step.Kind)
	note := strings.TrimSpace(step.Note)
	if step.Entity != nil {
		entity := string(step.Entity.Kind) + ":" + step.Entity.ID
		if step.Entity.Name != "" {
			entity = step.Entity.Name
		}
		if note == "" {
			return kind + " " + entity
		}
		return kind + " " + entity + " — " + note
	}
	if note == "" {
		if step.Span.File != "" {
			return kind
		}
		return ""
	}
	if kind == "" || kind == string(analysis.EvidenceNote) {
		return note
	}
	return kind + " " + note
}
