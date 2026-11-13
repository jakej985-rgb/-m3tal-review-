package analysis

import "strings"

// EvidenceKind classifies the role an EvidenceStep plays in a trace.
// The kinds cover the trace shapes required by the analysis contract:
// source-to-sink paths (EvidenceSource/EvidenceSink), call chains
// (EvidenceCall), control-flow paths (EvidenceBranch), state transitions
// (EvidenceState), and lock/critical-section sequences (EvidenceLock).
// EvidenceNote carries free-form observations that do not fit a
// structural role.
type EvidenceKind string

const (
	// EvidenceSource marks where untrusted or tainted data enters the
	// analyzed region (e.g. a request parameter, a file read).
	EvidenceSource EvidenceKind = "source"
	// EvidenceSink marks where data is consumed in a way that could
	// violate a property (e.g. a SQL query, an exec call, a write).
	EvidenceSink EvidenceKind = "sink"
	// EvidenceCall marks a call-chain hop: an entry or exit of a function
	// on the path between source and sink.
	EvidenceCall EvidenceKind = "call"
	// EvidenceBranch marks a control-flow decision point on the path
	// (a branch that was taken, or had to be taken, for the violation).
	EvidenceBranch EvidenceKind = "branch"
	// EvidenceState marks a state transition relevant to the finding
	// (e.g. lock acquired/released, object lifecycle change).
	EvidenceState EvidenceKind = "state"
	// EvidenceLock marks an event in a lock/critical-section sequence
	// (acquire, release, or a section boundary).
	EvidenceLock EvidenceKind = "lock"
	// EvidenceNote is a free-form observation attached to the trace.
	EvidenceNote EvidenceKind = "note"
)

// Valid reports whether the kind is recognized.
func (k EvidenceKind) Valid() bool {
	switch k {
	case EvidenceSource, EvidenceSink, EvidenceCall, EvidenceBranch,
		EvidenceState, EvidenceLock, EvidenceNote:
		return true
	}
	return false
}

// EvidenceStep is one ordered step in a finding's evidence trace. Steps
// are ordered by slice position: index 0 is the first event on the path
// (typically the source or entry point), and the last step typically
// reaches the sink or violating state.
//
// A step must carry at least one of Entity, Span, or Note; steps that
// carry none are rejected by Finding.Validate.
type EvidenceStep struct {
	Kind EvidenceKind `json:"kind"`
	// Entity optionally references the semantic entity the step
	// concerns (by stable ID; see EntityRef).
	Entity *EntityRef `json:"entity,omitempty"`
	// Span optionally locates the step in source.
	Span Span `json:"span,omitempty"`
	// Note is a human-readable explanation of the step. Notes are
	// excluded from identity hashing: rewording a note must not change
	// finding IDs, but changing kind, entity, or location does.
	Note string `json:"note,omitempty"`
	// Metadata carries optional structured annotations
	// (e.g. "may_set": "...", "depth": "3"). Keys should be
	// snake_case; values are display/debug data and are excluded from
	// identity hashing.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Identity returns the canonical serialization of the step used for
// finding-ID hashing. Only the structural content — kind, entity
// identity, and span — participates; Note and Metadata are excluded so
// that cosmetic edits do not churn identifiers.
func (s EvidenceStep) Identity() string {
	var b strings.Builder
	b.WriteString(string(s.Kind))
	b.WriteString("\x00")
	b.WriteString(s.Entity.Identity())
	b.WriteString("\x00")
	b.WriteString(s.Span.Key())
	return b.String()
}

// TraceKind names the shape of a finding's evidence trace.
type TraceKind string

const (
	// TraceSourceToSink is a data-flow path from an untrusted source to
	// a sensitive sink.
	TraceSourceToSink TraceKind = "source-to-sink"
	// TraceCallChain is a sequence of calls connecting entry points to
	// the violating operation.
	TraceCallChain TraceKind = "call-chain"
	// TraceControlFlow is a control-flow path through branches and joins.
	TraceControlFlow TraceKind = "control-flow"
	// TraceStateTransition is a sequence of state changes leading to the
	// violating state.
	TraceStateTransition TraceKind = "state-transition"
	// TraceLockSequence is a lock/critical-section event ordering.
	TraceLockSequence TraceKind = "lock-sequence"
	// TraceGeneral is an evidence trace that does not fit a named shape.
	TraceGeneral TraceKind = "general"
)

// Valid reports whether the kind is recognized.
func (k TraceKind) Valid() bool {
	switch k {
	case TraceSourceToSink, TraceCallChain, TraceControlFlow,
		TraceStateTransition, TraceLockSequence, TraceGeneral:
		return true
	}
	return false
}
