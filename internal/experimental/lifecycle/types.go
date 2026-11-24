package lifecycle

import (
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// State classifies the lifecycle status of a finding relative to baselines.
type State string

const (
	StateNew             State = "new"
	StateUnchanged       State = "unchanged"
	StateChanged         State = "changed"
	StateSeverityChanged State = "severity_changed"
	StateResolved        State = "resolved"
	StateReintroduced    State = "reintroduced"
)

// MatchKind indicates whether a finding was paired through exact or heuristic similarity.
type MatchKind string

const (
	MatchExact     MatchKind = "exact"
	MatchHeuristic MatchKind = "heuristic"
)

// BaselineEntry represents one finding preserved inside a baseline manifest.
type BaselineEntry struct {
	ID        string `json:"id"`
	Rule      string `json:"rule"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	Severity  string `json:"severity"`
	Snippet   string `json:"snippet,omitempty"`
	Signature string `json:"signature,omitempty"`
	Anchor    string `json:"anchor,omitempty"`
}

// BaselineManifest represents a versioned, integrity-protected baseline file.
type BaselineManifest struct {
	Version       string          `json:"version"`
	CreatedAt     time.Time       `json:"created_at"`
	CommitSHA     string          `json:"commit_sha,omitempty"`
	IntegrityHash string          `json:"integrity_hash"`
	Findings      []BaselineEntry `json:"findings"`
}

// LifecycleFinding attaches lifecycle and matching provenance to a finding.
type LifecycleFinding struct {
	Finding        review.Finding `json:"finding"`
	State          State          `json:"state"`
	Match          MatchKind      `json:"match"`
	BaselineID     string         `json:"baseline_id,omitempty"`
	TransitionNote string         `json:"transition_note,omitempty"`
}

// LifecycleResult summarizes the differential lifecycle analysis.
type LifecycleResult struct {
	ActiveFindings      []LifecycleFinding `json:"active_findings"`
	ResolvedFindings    []BaselineEntry    `json:"resolved_findings,omitempty"`
	NewCount            int                `json:"new_count"`
	UnchangedCount      int                `json:"unchanged_count"`
	ChangedCount        int                `json:"changed_count"`
	SeverityChangeCount int                `json:"severity_change_count"`
	ResolvedCount       int                `json:"resolved_count"`
	ReintroducedCount   int                `json:"reintroduced_count"`
}
