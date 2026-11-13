package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Finding is the shared analysis result contract. Every analyzer —
// built-in rules, semantic taint analyses, external plugins — emits this
// shape so findings are comparable across tools and reproducible across
// runs.
//
// Identity: ID is derived deterministically (see DeriveID) from the rule
// ID, the primary span, and the ordered evidence-step identities. Two
// runs over unchanged evidence produce the same ID; changing the rule,
// the location, or any structural evidence step changes it. Note text
// and metadata are deliberately excluded.
type Finding struct {
	// ID is the stable finding identifier: 16 lowercase hex characters,
	// derived from rule + primary span + evidence identities. Assign via
	// NewFinding/AssignFindingIDs; an empty ID is computed on demand by
	// DeriveID but should be persisted for consumers.
	ID string `json:"id"`

	// RuleID is the stable machine identifier of the rule that produced
	// the finding (e.g. "taint", "sqli"). Required.
	RuleID string `json:"rule_id"`
	// RuleName is an optional human-readable rule title.
	RuleName string `json:"rule_name,omitempty"`
	// Analyzer names the analyzer component (e.g. "go-semantic",
	// "plugin:semgrep"). Optional.
	Analyzer string `json:"analyzer,omitempty"`
	// RunID links the finding back to the Run that produced it.
	RunID string `json:"run_id,omitempty"`

	// Message is the human-readable description of the finding.
	// Required.
	Message string `json:"message"`
	// Category optionally groups findings ("security", "review",
	// "confidence", "risk", "drift" — matching review.ValidCategories).
	Category string `json:"category,omitempty"`
	// Severity uses the canonical review vocabulary:
	// info, low, medium, high, critical. Required.
	Severity string `json:"severity"`

	// Confidence qualifies how strongly the evidence supports the
	// conclusion. Empty is treated as ConfidenceUnknown.
	Confidence Confidence `json:"confidence,omitempty"`
	// Status is the epistemic status (proven/potential/unverified).
	// Required, and constrained by Truncation — see Status docs and
	// Validate.
	Status Status `json:"status"`
	// Trace names the evidence-trace shape (source-to-sink, call-chain,
	// control-flow, state-transition, lock-sequence, general).
	Trace TraceKind `json:"trace,omitempty"`

	// Spans are the source ranges the finding points at. The first span
	// is primary (used for identity and ordering); at least one span is
	// required.
	Spans []Span `json:"spans"`
	// Evidence is the ordered evidence trace: index 0 is the first
	// event on the path, the last step typically reaches the sink or
	// violating state.
	Evidence []EvidenceStep `json:"evidence,omitempty"`
	// Assumptions records conditions under which the conclusion holds
	// (e.g. "callee does not sanitize", "config flag disabled").
	Assumptions []string `json:"assumptions,omitempty"`
	// Truncation records incomplete analysis: exhausted budgets,
	// truncation reasons. Any incompleteness forbids StatusProven.
	Truncation Truncation `json:"truncation"`

	// Remediation suggests a fix.
	Remediation string `json:"remediation,omitempty"`
	// LegacyID preserves the identifier a finding had in the legacy
	// review report format, for cross-format correlation during
	// migration. It is informational and never used for identity.
	LegacyID string `json:"legacy_id,omitempty"`
	// Metadata carries optional structured annotations; excluded from
	// identity hashing.
	Metadata map[string]string `json:"metadata,omitempty"`
}

var validSeverities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}

// PrimarySpan returns the first span, or the zero Span when none exist.
func (f Finding) PrimarySpan() Span {
	if len(f.Spans) == 0 {
		return Span{}
	}
	return f.Spans[0]
}

// idDomain separates this hash construction from any other use of the
// same inputs (e.g. legacy finding IDs).
const idDomain = "m3tal-analysis-finding-v1"

// DeriveID computes the deterministic finding ID from the canonical
// serialization of rule ID + primary span + trace kind + ordered
// evidence-step identities. It returns 16 lowercase hex characters,
// matching the legacy review finding-ID format.
func (f Finding) DeriveID() string {
	return deriveIDWithOccurrence(f, 0)
}

func deriveIDWithOccurrence(f Finding, occurrence int) string {
	var b strings.Builder
	b.WriteString(idDomain)
	b.WriteString("\x00")
	b.WriteString(f.RuleID)
	b.WriteString("\x00")
	b.WriteString(f.PrimarySpan().Key())
	b.WriteString("\x00")
	b.WriteString(string(f.Trace))
	for _, step := range f.Evidence {
		b.WriteString("\x00")
		b.WriteString(step.Identity())
	}
	if occurrence > 0 {
		fmt.Fprintf(&b, "\x00%d", occurrence)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

// EnsureID populates f.ID with DeriveID when empty and returns f.
func (f Finding) EnsureID() Finding {
	if f.ID == "" {
		f.ID = f.DeriveID()
	}
	return f
}

// NewFinding builds a Finding with its ID derived and evidence ordered
// as given. Callers may still override fields afterwards; re-run
// AssignFindingIDs before serializing a set.
func NewFinding(f Finding) Finding {
	return f.EnsureID()
}

// Validate checks the finding against the contract invariants and
// returns all violations found. The critical rule: a finding whose
// analysis was incomplete (Truncation.Complete() == false) or that has
// no evidence trace can never be StatusProven.
func (f Finding) Validate() error {
	var errs []string
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	if strings.TrimSpace(f.RuleID) == "" {
		add("rule_id is required")
	}
	if strings.TrimSpace(f.Message) == "" {
		add("message is required")
	}
	if !validSeverities[strings.ToLower(strings.TrimSpace(f.Severity))] {
		add("severity %q is invalid; valid: info, low, medium, high, critical", f.Severity)
	}
	if f.Confidence != "" && !f.Confidence.Valid() {
		add("confidence %q is invalid; valid: high, medium, low, unknown", f.Confidence)
	}
	if !f.Status.Valid() {
		add("status %q is invalid; valid: proven, potential, unverified", f.Status)
	}
	if f.Trace != "" && !f.Trace.Valid() {
		add("trace %q is invalid", f.Trace)
	}
	if len(f.Spans) == 0 {
		add("at least one source span is required")
	} else if !f.PrimarySpan().Valid() {
		add("primary span must have a non-empty file")
	}
	for i, step := range f.Evidence {
		if !step.Kind.Valid() {
			add("evidence[%d].kind %q is invalid", i, step.Kind)
		}
		if step.Entity != nil && !step.Entity.Valid() {
			add("evidence[%d].entity is invalid (kind and id are required)", i)
		}
		if step.Entity == nil && step.Span.Empty() && strings.TrimSpace(step.Note) == "" {
			add("evidence[%d] carries no entity, span, or note", i)
		}
	}

	// The honesty invariant: incomplete analysis cannot be proven.
	if f.Status == StatusProven {
		if !f.Truncation.Complete() {
			add("status proven requires complete analysis, but truncation was recorded")
		}
		if len(f.Evidence) == 0 {
			add("status proven requires at least one evidence step")
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("invalid analysis finding: %s", strings.Join(errs, "; "))
}

// MarshalJSON enforces the contract at the serialization boundary: a
// finding that fails Validate — in particular a proven finding backed
// by truncated or absent evidence — cannot be serialized at all.
func (f Finding) MarshalJSON() ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	type plain Finding
	return json.Marshal(plain(f))
}

// SortFindings orders findings deterministically: by primary span file,
// then start offset/line/column, then rule ID, message, and ID. Sorting
// never reorders the evidence steps within a finding — their order is
// semantic.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i].PrimarySpan(), fs[j].PrimarySpan()
		if a.File != b.File {
			return a.File < b.File
		}
		if a.StartOffset != b.StartOffset {
			return a.StartOffset < b.StartOffset
		}
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}
		if a.StartColumn != b.StartColumn {
			return a.StartColumn < b.StartColumn
		}
		if fs[i].RuleID != fs[j].RuleID {
			return fs[i].RuleID < fs[j].RuleID
		}
		if fs[i].Message != fs[j].Message {
			return fs[i].Message < fs[j].Message
		}
		return fs[i].ID < fs[j].ID
	})
}

// AssignFindingIDs ensures every finding has an ID and resolves
// collisions deterministically. Findings whose derived IDs collide
// (identical rule, span, and evidence) are disambiguated by occurrence
// index after sorting candidates by their full canonical key, mirroring
// the legacy review.AssignFindingIDs behavior.
func AssignFindingIDs(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}
	out := make([]Finding, len(findings))
	copy(out, findings)
	for i := range out {
		out[i] = out[i].EnsureID()
	}

	groups := make(map[string][]int)
	for i, f := range out {
		groups[f.ID] = append(groups[f.ID], i)
	}
	for _, idxs := range groups {
		if len(idxs) < 2 {
			continue
		}
		// Deterministic candidate order, then occurrence suffixes.
		sort.SliceStable(idxs, func(a, b int) bool {
			ia, ib := idxs[a], idxs[b]
			ka := out[ia].RuleID + "\x00" + out[ia].Message + "\x00" + out[ia].PrimarySpan().Key()
			kb := out[ib].RuleID + "\x00" + out[ib].Message + "\x00" + out[ib].PrimarySpan().Key()
			if ka != kb {
				return ka < kb
			}
			return out[ia].ID < out[ib].ID
		})
		for occ, idx := range idxs {
			out[idx].ID = deriveIDWithOccurrence(out[idx], occ)
		}
	}
	return out
}
