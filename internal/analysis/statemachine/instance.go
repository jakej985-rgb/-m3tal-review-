package statemachine

import (
	"sort"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis/flow"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// This file resolves contract instances: which semantic value passed
// as an event's subject argument denotes which resource instance.
// Instance identity is a *set of root places* — package globals and
// allocation sites — computed through the flow analyzer's place facts
// and propagated backwards through call parameters. The result is a
// may-key: it over-approxims when the analysis cannot prove a unique
// instance, which can produce potential (never proven) findings.

// maxInstanceRoots bounds the number of root places folded into one
// instance key; overflow collapses to an "?" marker.
const maxInstanceRoots = 32

// maxInstanceDepth bounds parameter-chasing recursion when resolving
// instance keys through call chains.
const maxInstanceDepth = 4

// instanceKey computes the instance key for the subject argument of a
// call site. site/call/callee describe the triggering call; argIdx is
// the event's subject_arg. A negative argIdx yields the shared "self"
// instance.
func (e *explorer) instanceKey(bc *BoundContract, site *semantic.Instruction, call *semantic.Call, callee *semantic.Function, argIdx int, caller *semantic.Function) string {
	if argIdx < 0 {
		return "self"
	}
	actuals := e.flow.ActualsFor(site, call, callee)
	if argIdx >= len(actuals) || actuals[argIdx] == nil {
		return "inst:?"
	}
	v := actuals[argIdx]
	roots := e.valueRoots(v, caller, 0, make(map[string]bool))
	if len(roots) == 0 {
		return "inst:?"
	}
	return "inst:" + strings.Join(roots, ",")
}

// valueRoots returns the sorted set of root place keys a value may
// denote within owner (nil owner for shared values).
func (e *explorer) valueRoots(v *semantic.Value, owner *semantic.Function, depth int, seen map[string]bool) []string {
	if v == nil || depth > maxInstanceDepth {
		return []string{"?"}
	}
	places := e.placesOf(v, owner)
	if len(places) == 0 {
		// Values with no place facts still have kind-based identity.
		switch v.Kind {
		case semantic.ValueGlobal:
			places = []flow.Place{{Kind: flow.PlaceGlobal, ID: v.ID}}
		case semantic.ValueParam:
			if owner != nil {
				if idx := paramIndex(owner, v); idx >= 0 {
					places = []flow.Place{{Kind: flow.PlaceParam, Index: idx}}
				}
			}
		case semantic.ValueFreeVar, semantic.ValueUnresolved:
			places = []flow.Place{{Kind: flow.PlaceUnknown}}
		default:
			return []string{"?"}
		}
	}
	set := make(map[string]bool)
	for _, p := range places {
		for _, k := range e.placeRoots(p, owner, depth, seen) {
			set[k] = true
			if len(set) >= maxInstanceRoots {
				set["?"] = true
				return sortedKeys(set)
			}
		}
	}
	return sortedKeys(set)
}

// placesOf returns the place set for v in owner, combining the flow
// analyzer's instruction-value facts with kind-based seeds for
// parameters, globals, and free variables. When the analyzer has no
// facts (e.g. load results, which read rather than denote a place),
// it falls back to the places of the defining instruction's operands,
// bounded by maxInstancePlacesDepth.
func (e *explorer) placesOf(v *semantic.Value, owner *semantic.Function) []flow.Place {
	return e.placesOfDepth(v, owner, 0)
}

const maxInstancePlacesDepth = 4

func (e *explorer) placesOfDepth(v *semantic.Value, owner *semantic.Function, depth int) []flow.Place {
	var out []flow.Place
	if owner != nil {
		out = append(out, e.flow.PlacesOf(owner, v)...)
	}
	switch v.Kind {
	case semantic.ValueGlobal:
		out = append(out, flow.Place{Kind: flow.PlaceGlobal, ID: v.ID})
	case semantic.ValueParam:
		if owner != nil {
			if idx := paramIndex(owner, v); idx >= 0 {
				out = append(out, flow.Place{Kind: flow.PlaceParam, Index: idx})
			}
		}
	case semantic.ValueFreeVar, semantic.ValueUnresolved:
		out = append(out, flow.Place{Kind: flow.PlaceUnknown})
	}
	if len(out) == 0 && v.Def != nil && depth < maxInstancePlacesDepth {
		// Load/index results denote the *contents* of a place; the
		// instance they carry is identified by the place they were
		// read through, so union the operands' places.
		for _, op := range v.Def.Operands {
			out = append(out, e.placesOfDepth(op, owner, depth+1)...)
		}
	}
	// Deduplicate.
	seen := make(map[flow.Place]bool)
	var dedup []flow.Place
	for _, p := range out {
		if !seen[p] {
			seen[p] = true
			dedup = append(dedup, p)
		}
	}
	return dedup
}

// placeRoots reduces one place to root keys, chasing parameter places
// back through recorded call sites.
func (e *explorer) placeRoots(p flow.Place, owner *semantic.Function, depth int, seen map[string]bool) []string {
	switch p.Kind {
	case flow.PlaceGlobal:
		return []string{"g:" + p.ID}
	case flow.PlaceLocal:
		return []string{"l:" + p.ID}
	case flow.PlaceUnknown:
		return []string{"?"}
	case flow.PlaceParam:
		if owner == nil || depth > maxInstanceDepth {
			return []string{"?"}
		}
		mark := owner.ID + "|" + strconv.Itoa(p.Index)
		if seen[mark] {
			return []string{"?"}
		}
		seen[mark] = true
		var keys []string
		for _, cs := range e.flow.CallSites(owner) {
			actuals := e.flow.ActualsFor(cs.Site, cs.Call, owner)
			if p.Index < 0 || p.Index >= len(actuals) || actuals[p.Index] == nil {
				continue
			}
			for _, k := range e.valueRoots(actuals[p.Index], cs.Caller, depth+1, seen) {
				keys = append(keys, k)
			}
		}
		if len(keys) == 0 {
			return []string{"?"}
		}
		return keys
	}
	return []string{"?"}
}

// paramIndex returns v's index among owner's ValueParam values
// (receiver first for methods), or -1.
func paramIndex(fn *semantic.Function, v *semantic.Value) int {
	idx := 0
	for _, pv := range fn.Values {
		if pv.Kind != semantic.ValueParam {
			continue
		}
		if pv == v {
			return idx
		}
		idx++
	}
	return -1
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
