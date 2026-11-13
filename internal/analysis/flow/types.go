package flow

import (
	"sort"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// OriginKind classifies an Origin: the semantic input a computed fact
// depends on.
type OriginKind int

const (
	// OriginParam is a function parameter. Index is the parameter's
	// position among the function's ValueParam values (index 0 is the
	// receiver for methods).
	OriginParam OriginKind = iota
	// OriginGlobal is a package-level variable; ID is the global
	// value's stable ID ("global:<pkg>.<name>").
	OriginGlobal
	// OriginFreeVar is a variable captured from an enclosing function;
	// Index is its position among the function's ValueFreeVar values.
	OriginFreeVar
	// OriginUnknown marks a dependence the analysis could not resolve
	// (unresolved operands, unanalyzable calls, values read through
	// unknown places).
	OriginUnknown
)

// Origin identifies one semantic input a data-flow fact depends on.
// Origins are function-relative for Param/FreeVar kinds and
// program-global for Global/Unknown kinds.
type Origin struct {
	Kind  OriginKind
	Index int    // parameter or free-variable index; -1 when unused
	ID    string // global value ID; "" when unused
}

// PlaceKind classifies a Place: a memory location a function may read
// or write.
type PlaceKind int

const (
	// PlaceGlobal is a package-level variable; ID is its value ID.
	PlaceGlobal PlaceKind = iota
	// PlaceParam is storage reachable through a parameter (the
	// parameter itself or memory it points to, including fields —
	// the model does not retain field indices, so all fields of a
	// parameter collapse to one place). Index is the parameter index.
	PlaceParam
	// PlaceLocal is function-local storage (allocations, address-
	// taken locals); ID is the allocating value's ID. Local places
	// are visible within the owning function's summary but are not
	// propagated to callers.
	PlaceLocal
	// PlaceUnknown is a location the analysis cannot name (e.g.
	// storage reached through an unanalyzable call result or a free
	// variable). Facts targeting PlaceUnknown are recorded, never
	// dropped.
	PlaceUnknown
)

// Place identifies a memory location. Two Places are equal only when
// Kind, ID, and Index all match.
type Place struct {
	Kind  PlaceKind
	ID    string // global value ID or local value ID; "" when unused
	Index int    // parameter index; -1 when unused
}

// Write records a may-write to a place. Sources are the Origins of the
// values that may flow into the location.
type Write struct {
	Target  Place
	Sources []Origin
}

// CallFact describes one call site and what the analysis could
// determine about it.
type CallFact struct {
	// Site is the call instruction.
	Site *semantic.Instruction
	// Position is the call site's source position.
	Position semantic.Position
	// Target is the frontend's human-readable callee description.
	Target string
	// Callees are the resolved callee function IDs (the model's
	// Call.Callees may-set), sorted. Empty with Dynamic=true means the
	// target could not be resolved at all.
	Callees []string
	// Dynamic reports that the frontend could not resolve the callee
	// statically.
	Dynamic bool
	// Unknown is true when the call's effects could not be fully
	// analyzed: unresolved dynamic target, external/bodiless callee,
	// callee outside the analysis budget, or an impure builtin.
	// Unknown calls never produce safe assumptions: their results are
	// tainted with OriginUnknown and the owning summary is flagged.
	Unknown bool
	// Reason explains Unknown (or notes an incomplete callee set).
	Reason string
	// Args records, per actual argument in operand order, the Origins
	// that may flow into it.
	Args [][]Origin
	// Results records, per callee result index, the Origins that may
	// flow out of the call (mapped through the callee's summary).
	Results [][]Origin
}

// Summary is the computed effect summary for one function.
type Summary struct {
	// Function is the summarized function.
	Function *semantic.Function
	// Reads lists the places the function may read (loads, indexing,
	// receives, and reads propagated from callees), sorted.
	Reads []Place
	// Writes lists the places the function may write, including
	// writes propagated from callees (callee parameter writes are
	// mapped onto the caller's actual arguments). Sorted by Target.
	Writes []Write
	// Calls lists the function's call sites in instruction order.
	Calls []*CallFact
	// Returns has one entry per signature result, listing the Origins
	// that may flow into that result.
	Returns [][]Origin
	// Unknown is true when the function has effects the analysis
	// could not resolve (see Reasons).
	Unknown bool
	// Truncated is true when a budget (MaxOrigins, MaxRounds, or
	// MaxFunctions on a callee) limited this summary.
	Truncated bool
	// Reasons explains Unknown/Truncated flags. Sorted, deduplicated.
	Reasons []string
}

// originSet is a deduplicating set of Origins.
type originSet map[Origin]struct{}

func newOriginSet() originSet { return make(originSet) }

func (s originSet) add(o Origin) {
	if o.Kind == OriginParam || o.Kind == OriginFreeVar {
		if o.Index < 0 {
			o.Index = 0
		}
	}
	s[o] = struct{}{}
}

func (s originSet) union(other originSet) {
	for o := range other {
		s[o] = struct{}{}
	}
}

func (s originSet) hasUnknown() bool {
	for o := range s {
		if o.Kind == OriginUnknown {
			return true
		}
	}
	return false
}

// sorted returns the set's origins in deterministic order.
func (s originSet) sorted() []Origin {
	out := make([]Origin, 0, len(s))
	for o := range s {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Index != out[j].Index {
			return out[i].Index < out[j].Index
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// placeSet is a deduplicating set of Places.
type placeSet map[Place]struct{}

func newPlaceSet() placeSet { return make(placeSet) }

func (s placeSet) add(p Place) {
	if p.Kind == PlaceParam && p.Index < 0 {
		p.Index = 0
	}
	s[p] = struct{}{}
}

func (s placeSet) union(other placeSet) {
	for p := range other {
		s[p] = struct{}{}
	}
}

func (s placeSet) sorted() []Place {
	out := make([]Place, 0, len(s))
	for p := range s {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Index < out[j].Index
	})
	return out
}

// hasUnknown reports whether the set contains PlaceUnknown.
func (s placeSet) hasUnknown() bool {
	for p := range s {
		if p.Kind == PlaceUnknown {
			return true
		}
	}
	return false
}

func appendUnique(xs []string, x string) []string {
	for _, e := range xs {
		if e == x {
			return xs
		}
	}
	return append(xs, x)
}

// summaryEqual reports whether two summaries carry identical facts.
// It ignores the Function pointer identity only in that both must be
// non-nil; call Site pointers are compared by identity, which is valid
// because both summaries describe the same program.
func summaryEqual(a, b *Summary) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Unknown != b.Unknown || a.Truncated != b.Truncated || len(a.Reasons) != len(b.Reasons) {
		return false
	}
	for i := range a.Reasons {
		if a.Reasons[i] != b.Reasons[i] {
			return false
		}
	}
	if !placeSliceEqual(a.Reads, b.Reads) {
		return false
	}
	if len(a.Writes) != len(b.Writes) {
		return false
	}
	for i := range a.Writes {
		if a.Writes[i].Target != b.Writes[i].Target || !originSliceEqual(a.Writes[i].Sources, b.Writes[i].Sources) {
			return false
		}
	}
	if len(a.Calls) != len(b.Calls) {
		return false
	}
	for i := range a.Calls {
		if !callFactEqual(a.Calls[i], b.Calls[i]) {
			return false
		}
	}
	if len(a.Returns) != len(b.Returns) {
		return false
	}
	for i := range a.Returns {
		if !originSliceEqual(a.Returns[i], b.Returns[i]) {
			return false
		}
	}
	return true
}

func placeSliceEqual(a, b []Place) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func originSliceEqual(a, b []Origin) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func originSetsEqual(a, b [][]Origin) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !originSliceEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

func callFactEqual(a, b *CallFact) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Site != b.Site || a.Target != b.Target || a.Dynamic != b.Dynamic ||
		a.Unknown != b.Unknown || a.Reason != b.Reason ||
		a.Position.File != b.Position.File || a.Position.Line != b.Position.Line ||
		a.Position.Column != b.Position.Column {
		return false
	}
	if len(a.Callees) != len(b.Callees) {
		return false
	}
	for i := range a.Callees {
		if a.Callees[i] != b.Callees[i] {
			return false
		}
	}
	if len(a.Args) != len(b.Args) {
		return false
	}
	for i := range a.Args {
		if !originSliceEqual(a.Args[i], b.Args[i]) {
			return false
		}
	}
	return originSetsEqual(a.Results, b.Results)
}
