package concurrency

import (
	"sort"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis/flow"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// atomKind classifies one component of a stateKey: either a memory
// place (where state lives) or an origin (what a value derives from,
// used as a fallback identity when no place facts exist).
type atomKind int

const (
	atomPlaceGlobal atomKind = iota
	atomPlaceParam
	atomPlaceLocal
	atomPlaceUnknown
	atomOriginGlobal
	atomOriginParam
	atomOriginFreeVar
	atomOriginUnknown
)

// atom is the smallest unit of shared-state identity. Atoms are always
// interpreted relative to a scope: function-relative atoms (parameter
// places/origins, free variables, locals, unknown places) carry the
// owning function's ID in Scope; globals and unknown origins are
// unscoped.
type atom struct {
	kind  atomKind
	scope string // function ID for function-relative atoms; "" otherwise
	id    string // global or local value ID; "" when unused
	index int    // parameter or free-variable index; -1 when unused
}

func atomLess(a, b atom) bool {
	if a.kind != b.kind {
		return a.kind < b.kind
	}
	if a.scope != b.scope {
		return a.scope < b.scope
	}
	if a.id != b.id {
		return a.id < b.id
	}
	return a.index < b.index
}

func sortAtoms(as []atom) {
	sort.Slice(as, func(i, j int) bool { return atomLess(as[i], as[j]) })
}

// stateKey identifies a candidate shared-state location (or, when no
// place facts exist, a value-derivation set standing in for one).
// Exactly one of places/origins is non-empty.
//
//   - places: memory places the accessed-through value may denote.
//     Two accesses conflict when their place-atom sets intersect
//     (may-alias: sharing any one place is enough).
//   - origins: provenance atoms used when the flow analyzer produced
//     no place facts (e.g. values loaded through pointers or returned
//     from calls). Two origin keys conflict when one atom set is a
//     subset of the other — the derivations are compatible.
type stateKey struct {
	places  []atom
	origins []atom
}

func (k stateKey) empty() bool { return len(k.places) == 0 && len(k.origins) == 0 }

func (k stateKey) isPlaceKey() bool { return len(k.places) > 0 }

// conflicts reports whether two keys may denote the same state.
func (k stateKey) conflicts(o stateKey) bool {
	if k.isPlaceKey() && o.isPlaceKey() {
		for _, a := range k.places {
			for _, b := range o.places {
				if a == b {
					return true
				}
			}
		}
		return false
	}
	if !k.isPlaceKey() && !o.isPlaceKey() && len(k.origins) > 0 && len(o.origins) > 0 {
		return originSubset(k.origins, o.origins) || originSubset(o.origins, k.origins)
	}
	return false
}

// originSubset reports whether every atom of sub appears in sup.
func originSubset(sub, sup []atom) bool {
	if len(sub) > len(sup) {
		return false
	}
	set := make(map[atom]bool, len(sup))
	for _, a := range sup {
		set[a] = true
	}
	for _, a := range sub {
		if !set[a] {
			return false
		}
	}
	return true
}

// String returns a canonical, deterministic rendering used for
// deduplication, reporting, and finding metadata.
func (k stateKey) String() string {
	var b strings.Builder
	if k.isPlaceKey() {
		b.WriteString("place{")
		for i, a := range k.places {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(atomString(a))
		}
		b.WriteByte('}')
		return b.String()
	}
	b.WriteString("origin{")
	for i, a := range k.origins {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(atomString(a))
	}
	b.WriteByte('}')
	return b.String()
}

func atomString(a atom) string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(int(a.kind)))
	b.WriteByte(':')
	b.WriteString(a.scope)
	b.WriteByte(':')
	b.WriteString(a.id)
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(a.index))
	return b.String()
}

// ---------------------------------------------------------------------
// Key construction and translation
// ---------------------------------------------------------------------

// valueKeys computes the state keys a value may denote within fn.
// Intrinsic kinds (globals, parameters, free variables) seed their
// own identities — mirroring the flow analyzer's internal origin
// rules, which the exported PlacesOf/DepsOf queries do not expose for
// non-instruction values. Instruction values use the accumulated flow
// facts, preferring places and falling back to dependence origins
// (also when the only places are PlaceUnknown, which carry no
// distinguishing identity). It returns nil when the value carries no
// usable location information.
func (a *Analyzer) valueKeys(fn *semantic.Function, v *semantic.Value) []stateKey {
	if fn == nil || v == nil {
		return nil
	}
	switch v.Kind {
	case semantic.ValueGlobal:
		return []stateKey{{places: []atom{{kind: atomPlaceGlobal, id: v.ID}}}}
	case semantic.ValueParam:
		return []stateKey{{places: []atom{{
			kind:  atomPlaceParam,
			scope: fn.ID,
			index: a.canonParamIndex(fn.ID, a.valueIndex(fn, v, true)),
		}}}}
	case semantic.ValueFreeVar:
		return []stateKey{{origins: []atom{{
			kind:  atomOriginFreeVar,
			scope: fn.ID,
			index: a.valueIndex(fn, v, false),
		}}}}
	case semantic.ValueUnresolved:
		return []stateKey{{origins: []atom{{kind: atomOriginUnknown}}}}
	case semantic.ValueConst, semantic.ValueFunction, semantic.ValueBuiltin:
		return nil
	}

	var placeAtoms, originAtoms []atom
	if places := a.flow.PlacesOf(fn, v); len(places) > 0 {
		for _, p := range places {
			placeAtoms = append(placeAtoms, a.placeAtom(p, fn.ID))
		}
	}
	if deps := a.flow.DepsOf(fn, v); len(deps) > 0 {
		for _, o := range deps {
			originAtoms = append(originAtoms, a.originAtom(o, fn.ID))
		}
	}
	switch {
	case len(placeAtoms) > 0 && !allUnknownPlaceAtoms(placeAtoms):
		sortAtoms(placeAtoms)
		return []stateKey{{places: dedupAtoms(placeAtoms)}}
	case len(originAtoms) > 0:
		sortAtoms(originAtoms)
		return []stateKey{{origins: dedupAtoms(originAtoms)}}
	case len(placeAtoms) > 0:
		sortAtoms(placeAtoms)
		return []stateKey{{places: dedupAtoms(placeAtoms)}}
	}
	return nil
}

// allUnknownPlaceAtoms reports whether every atom is an unknown place.
func allUnknownPlaceAtoms(as []atom) bool {
	for _, a := range as {
		if a.kind != atomPlaceUnknown {
			return false
		}
	}
	return len(as) > 0
}

// valueIndex returns a value's index among the function's parameters
// (isParam) or free variables, or -1 when not found.
func (a *Analyzer) valueIndex(fn *semantic.Function, v *semantic.Value, isParam bool) int {
	if a.valueIdx == nil {
		a.valueIdx = make(map[*semantic.Function]*fnValueIndex)
	}
	vi := a.valueIdx[fn]
	if vi == nil {
		vi = &fnValueIndex{params: make(map[*semantic.Value]int), frees: make(map[*semantic.Value]int)}
		for _, fv := range fn.Values {
			switch fv.Kind {
			case semantic.ValueParam:
				vi.params[fv] = len(vi.params)
			case semantic.ValueFreeVar:
				vi.frees[fv] = len(vi.frees)
			}
		}
		a.valueIdx[fn] = vi
	}
	if isParam {
		return vi.params[v]
	}
	return vi.frees[v]
}

// fnValueIndex caches parameter/free-variable positions per function.
type fnValueIndex struct {
	params map[*semantic.Value]int
	frees  map[*semantic.Value]int
}

func dedupAtoms(as []atom) []atom {
	if len(as) < 2 {
		return as
	}
	out := as[:1]
	for _, x := range as[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}

func (a *Analyzer) placeAtom(p flow.Place, scope string) atom {
	switch p.Kind {
	case flow.PlaceGlobal:
		return atom{kind: atomPlaceGlobal, id: p.ID}
	case flow.PlaceParam:
		return atom{kind: atomPlaceParam, scope: scope, index: a.canonParamIndex(scope, p.Index)}
	case flow.PlaceLocal:
		return atom{kind: atomPlaceLocal, scope: scope, id: p.ID}
	default: // flow.PlaceUnknown
		return atom{kind: atomPlaceUnknown, scope: scope}
	}
}

func (a *Analyzer) originAtom(o flow.Origin, scope string) atom {
	switch o.Kind {
	case flow.OriginGlobal:
		return atom{kind: atomOriginGlobal, id: o.ID}
	case flow.OriginParam:
		return atom{kind: atomOriginParam, scope: scope, index: a.canonParamIndex(scope, o.Index)}
	case flow.OriginFreeVar:
		return atom{kind: atomOriginFreeVar, scope: scope, index: o.Index}
	default: // flow.OriginUnknown
		return atom{kind: atomOriginUnknown}
	}
}

// translateKeys re-interprets keys computed in calleeFn's scope in the
// caller's context, using the actual arguments at the call site. This
// mirrors the place/origin mapping the flow analyzer performs for
// summaries, but preserves per-access granularity for critical-section
// attribution.
//
// Rules:
//   - function-relative atoms scoped to calleeFn are resolved through
//     the corresponding actual argument (param places/origins);
//   - free-variable atoms keep their scope: a captured variable belongs
//     to the callee's defining context regardless of the caller;
//   - global atoms pass through; local atoms are dropped (callee-local
//     storage is invisible to the caller); unknown places keep their
//     scope rather than risking false cross-function matches.
func (a *Analyzer) translateKeys(keys []stateKey, caller *semantic.Function, callee *semantic.Function, actuals []*semantic.Value) []stateKey {
	var out []stateKey
	for _, k := range keys {
		out = append(out, a.translateKey(k, caller, callee, actuals)...)
	}
	return out
}

func (a *Analyzer) translateKey(k stateKey, caller, callee *semantic.Function, actuals []*semantic.Value) []stateKey {
	if k.isPlaceKey() {
		var places, origins []atom
		for _, pa := range k.places {
			if pa.scope != callee.ID {
				// Global, or scoped to some other (deeper) function.
				if pa.kind == atomPlaceLocal {
					continue // locals never cross call boundaries
				}
				places = append(places, pa)
				continue
			}
			switch pa.kind {
			case atomPlaceGlobal:
				places = append(places, pa)
			case atomPlaceParam:
				a.resolveActual(&places, &origins, caller, actuals, pa.index)
			case atomPlaceLocal:
				// Callee-local storage: not visible to the caller.
			case atomPlaceUnknown:
				places = append(places, pa)
			}
		}
		return keysFromAtoms(places, origins)
	}

	var places, origins []atom
	for _, oa := range k.origins {
		if oa.scope != callee.ID {
			origins = append(origins, oa)
			continue
		}
		switch oa.kind {
		case atomOriginGlobal, atomOriginUnknown:
			origins = append(origins, oa)
		case atomOriginParam:
			// Parameter origins resolve through the actual's own
			// keys: place facts when available, origin atoms
			// otherwise.
			var actual *semantic.Value
			if oa.index >= 0 && oa.index < len(actuals) {
				actual = actuals[oa.index]
			}
			if actual == nil {
				origins = append(origins, atom{kind: atomOriginUnknown})
				continue
			}
			for _, k := range a.valueKeys(caller, actual) {
				origins = append(origins, k.origins...)
				places = append(places, k.places...)
			}
		case atomOriginFreeVar:
			// The callee's captured variables are not the caller's;
			// keep the original scope.
			origins = append(origins, oa)
		}
	}
	return keysFromAtoms(places, origins)
}

// resolveActual maps a callee parameter place onto the caller's view
// of the corresponding actual argument, appending the atoms of the
// actual's own state keys.
func (a *Analyzer) resolveActual(places, origins *[]atom, caller *semantic.Function, actuals []*semantic.Value, index int) {
	var actual *semantic.Value
	if index >= 0 && index < len(actuals) {
		actual = actuals[index]
	}
	if actual == nil {
		*places = append(*places, atom{kind: atomPlaceUnknown, scope: caller.ID})
		return
	}
	merged := false
	for _, k := range a.valueKeys(caller, actual) {
		merged = true
		*places = append(*places, k.places...)
		*origins = append(*origins, k.origins...)
	}
	if !merged {
		*places = append(*places, atom{kind: atomPlaceUnknown, scope: caller.ID})
	}
}

// keysFromAtoms packs translated atoms back into state keys: place
// atoms form one place key, origin atoms one origin key.
func keysFromAtoms(places, origins []atom) []stateKey {
	var out []stateKey
	if len(places) > 0 {
		sortAtoms(places)
		out = append(out, stateKey{places: dedupAtoms(places)})
	}
	if len(origins) > 0 {
		sortAtoms(origins)
		out = append(out, stateKey{origins: dedupAtoms(origins)})
	}
	return out
}

// keysConflict reports whether any key in a conflicts with any key in b.
func keysConflict(a, b []stateKey) bool {
	for _, ka := range a {
		for _, kb := range b {
			if ka.conflicts(kb) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------
// Parameter aliasing
// ---------------------------------------------------------------------

// canonParamIndex maps a parameter index to its canonical
// representative under observed argument aliasing (e.g. f(s, s)
// aliases parameters 0 and 1). Indices without alias information pass
// through unchanged.
func (a *Analyzer) canonParamIndex(fnID string, idx int) int {
	if idx < 0 {
		return idx
	}
	rep, ok := a.paramAlias[fnID]
	if !ok || idx >= len(rep) {
		return idx
	}
	return rep[idx]
}

// computeParamAliases unions parameter indices that receive the same
// actual argument value at any observed call site. This is a
// may-analysis: parameters aliased at one site are treated as aliased
// everywhere, which can merge distinct objects (documented
// limitation).
func (a *Analyzer) computeParamAliases() {
	type uf struct{ parent []int }
	find := func(u *uf, x int) int {
		for u.parent[x] != x {
			u.parent[x] = u.parent[u.parent[x]]
			x = u.parent[x]
		}
		return x
	}
	ufs := make(map[string]*uf)
	ufFor := func(id string, n int) *uf {
		u := ufs[id]
		if u == nil {
			u = &uf{parent: make([]int, n)}
			for i := range u.parent {
				u.parent[i] = i
			}
			ufs[id] = u
		}
		for len(u.parent) < n {
			u.parent = append(u.parent, len(u.parent))
		}
		return u
	}
	for _, pkg := range a.prog.Packages {
		for _, fn := range pkg.Functions {
			for _, call := range fn.Calls {
				for _, callee := range call.Callees {
					if callee == nil || len(callee.Blocks) == 0 {
						continue
					}
					actuals := a.flow.ActualsFor(call.Site, call, callee)
					if len(actuals) == 0 {
						continue
					}
					u := ufFor(callee.ID, len(actuals))
					first := make(map[*semantic.Value]int)
					for i, av := range actuals {
						if av == nil {
							continue
						}
						if j, ok := first[av]; ok {
							ri, rj := find(u, i), find(u, j)
							if ri != rj {
								u.parent[ri] = rj
							}
						} else {
							first[av] = i
						}
					}
				}
			}
		}
	}
	for id, u := range ufs {
		rep := make([]int, len(u.parent))
		for i := range rep {
			rep[i] = find(u, i)
		}
		a.paramAlias[id] = rep
	}
}
