package analysis

import "strings"

// Status is the epistemic status of a finding: what the analyzer
// actually established.
//
//   - StatusProven: the violation is established by complete evidence —
//     a full trace with no truncation, no budget exhaustion, and no
//     unresolved assumptions that would invalidate the conclusion.
//     Proven findings MUST satisfy Finding.Validate; in particular a
//     finding whose analysis was truncated can never be proven, and
//     Finding.MarshalJSON refuses to serialize one.
//   - StatusPotential: evidence suggests a violation but the proof is
//     incomplete — e.g. a may-call target, an unbounded path that was
//     cut short, or a heuristic match. Potential findings may carry
//     truncation information.
//   - StatusUnverified: the analyzer could not verify the property at
//     all — unsupported constructs, exhausted budgets, or missing
//     semantic information. Use this instead of silence so consumers can
//     distinguish "checked and clean-ish" from "never checked".
//
// The zero value is invalid; every finding must declare a status.
type Status string

const (
	StatusProven     Status = "proven"
	StatusPotential  Status = "potential"
	StatusUnverified Status = "unverified"
)

// Valid reports whether the status is recognized.
func (s Status) Valid() bool {
	return s == StatusProven || s == StatusPotential || s == StatusUnverified
}

// ParseStatus maps a string to a Status, accepting the canonical values
// case-insensitively. It returns ok=false for unrecognized input.
func ParseStatus(s string) (Status, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "proven":
		return StatusProven, true
	case "potential":
		return StatusPotential, true
	case "unverified":
		return StatusUnverified, true
	}
	return "", false
}

// Confidence expresses how strongly the evidence supports the finding's
// conclusion, independent of Status: a proven finding can still carry
// low confidence when the rule itself is heuristic, and a potential
// finding can carry high confidence in its suspicion.
//
// The vocabulary intentionally matches review.NormalizeConfidence
// ("high"/"medium"/"low") plus "unknown" for "no confidence expressed".
// It is NOT the same type as internal/review/language.Confidence, which
// is capitalized and measures language-detection certainty — see the
// package doc for the reconciliation.
type Confidence string

const (
	ConfidenceHigh    Confidence = "high"
	ConfidenceMedium  Confidence = "medium"
	ConfidenceLow     Confidence = "low"
	ConfidenceUnknown Confidence = "unknown"
)

// Valid reports whether the confidence is recognized. The empty string
// is treated as ConfidenceUnknown by callers.
func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow, ConfidenceUnknown:
		return true
	}
	return false
}

// Rank orders confidences for aggregation; higher is more confident.
// Unknown ranks below low.
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// ParseConfidence maps a free-form confidence string onto the canonical
// vocabulary, mirroring review.NormalizeConfidence's keyword handling
// ("high"/"certain"/"definite" → high, etc.). Unrecognized or empty
// input yields ConfidenceUnknown so consumers never see invalid values.
func ParseConfidence(s string) Confidence {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high", "certain", "definite":
		return ConfidenceHigh
	case "medium", "moderate", "likely":
		return ConfidenceMedium
	case "low", "unconfirmed", "experimental":
		return ConfidenceLow
	default:
		return ConfidenceUnknown
	}
}

// Budget records one path/iteration/resource limit relevant to an
// analysis run or finding, and whether it was exhausted.
type Budget struct {
	// Name identifies the limit, e.g. "max-paths", "max-call-depth",
	// "max-iterations", "max-evidence-steps".
	Name string `json:"name"`
	// Limit is the configured bound; 0 means unbounded/unknown.
	Limit int `json:"limit,omitempty"`
	// Used is how much of the budget was consumed when the run stopped.
	Used int `json:"used,omitempty"`
	// Truncated is true when the bound was hit and results were cut.
	Truncated bool `json:"truncated,omitempty"`
}

// Truncation records that analysis was incomplete: which budgets were
// exhausted, why results were cut, and whether the finding's evidence
// should be considered partial.
//
// A zero Truncation is complete. Any Truncated flag, reason, or
// truncated budget makes the analysis incomplete, which forbids
// StatusProven.
type Truncation struct {
	// Truncated is the coarse flag; true whenever any listed reason or
	// budget indicates incompleteness.
	Truncated bool `json:"truncated,omitempty"`
	// Reasons are human-readable explanations (e.g. "call graph depth
	// exceeded", "unsupported: cgo").
	Reasons []string `json:"reasons,omitempty"`
	// Budgets are the specific path/iteration budgets that were hit.
	Budgets []Budget `json:"budgets,omitempty"`
}

// Complete reports whether the analysis backing a finding ran to
// completion with no truncation. Only complete analyses may be proven.
func (t Truncation) Complete() bool {
	if t.Truncated || len(t.Reasons) > 0 {
		return false
	}
	for _, b := range t.Budgets {
		if b.Truncated {
			return false
		}
	}
	return true
}
