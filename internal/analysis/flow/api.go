package flow

import "github.com/jakej985-rgb/m3tal-review/internal/semantic"

// CallSite describes one call edge into a function: the caller, the
// call instruction, and the frontend's Call record. It is the exported
// view of the caller index used by Flow's interprocedural queries.
type CallSite struct {
	// Caller is the function containing the call.
	Caller *semantic.Function
	// Site is the call instruction.
	Site *semantic.Instruction
	// Call is the modeled call (callee may-set, kind, target text).
	Call *semantic.Call
}

// CallSites returns the recorded call sites that may invoke fn,
// ordered by caller function ID then instruction order. It returns nil
// for functions with no modeled callers (entry points, unused
// functions) and for functions the analyzer never summarized.
func (a *Analyzer) CallSites(fn *semantic.Function) []*CallSite {
	if fn == nil {
		return nil
	}
	refs := a.callersOf(fn)
	out := make([]*CallSite, 0, len(refs))
	for _, r := range refs {
		if r == nil || r.caller == nil || r.site == nil || r.call == nil {
			continue
		}
		out = append(out, &CallSite{Caller: r.caller, Site: r.site, Call: r.call})
	}
	// callersOf appends in package/function iteration order, which is
	// already deterministic; sort defensively for hand-built indexes.
	sortCallSites(out)
	return out
}

func sortCallSites(sites []*CallSite) {
	// Insertion sort: caller counts are small and the input is nearly
	// sorted already.
	for i := 1; i < len(sites); i++ {
		for j := i; j > 0; j-- {
			a, b := sites[j-1], sites[j]
			if callSiteLess(a, b) {
				break
			}
			sites[j-1], sites[j] = sites[j], sites[j-1]
		}
	}
}

func callSiteLess(a, b *CallSite) bool {
	if a.Caller.ID != b.Caller.ID {
		return a.Caller.ID < b.Caller.ID
	}
	return a.Site.ID < b.Site.ID
}

// ActualsFor aligns a call site's operands to callee's parameter list
// and returns one entry per parameter (index 0 is the receiver for
// methods). Entries are nil where no actual exists. It is the exported
// form of the alignment used internally for summary propagation.
func (a *Analyzer) ActualsFor(site *semantic.Instruction, call *semantic.Call, callee *semantic.Function) []*semantic.Value {
	return a.actualsFor(site, call, callee)
}

// ParamValues returns the function's parameter values (including the
// receiver at index 0 for methods) in declaration order.
func (a *Analyzer) ParamValues(fn *semantic.Function) []*semantic.Value {
	return a.paramValues(fn)
}

// PlacesOf returns the memory places the value v may denote within
// function fn, as computed by the data-flow fixpoint. It returns nil
// when fn was not analyzed (external, bodiless, or beyond
// Options.MaxFunctions) or when v carries no place facts — callers
// must treat nil as "unknown location", never as "no places".
func (a *Analyzer) PlacesOf(fn *semantic.Function, v *semantic.Value) []Place {
	if fn == nil || v == nil {
		return nil
	}
	w := a.works[fn.ID]
	if w == nil {
		return nil
	}
	set := w.places[v]
	if len(set) == 0 {
		return nil
	}
	return set.sorted()
}

// DepsOf returns the Origins value v may depend on within function fn.
// Like PlacesOf, nil means "no facts" (unanalyzed function or value
// with no tracked dependence), not "depends on nothing".
func (a *Analyzer) DepsOf(fn *semantic.Function, v *semantic.Value) []Origin {
	if fn == nil || v == nil {
		return nil
	}
	w := a.works[fn.ID]
	if w == nil {
		return nil
	}
	set := w.deps[v]
	if len(set) == 0 {
		return nil
	}
	return set.sorted()
}
