package flow

import (
	"sort"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// fnWork is the per-function analysis state. deps, places, and
// placeWrites persist across fixpoint rounds and only grow (the
// analysis is a may-analysis); reads, writes, calls, and returns are
// rebuilt each round from the current facts.
type fnWork struct {
	a  *Analyzer
	fn *semantic.Function

	paramIndex map[*semantic.Value]int
	freeIndex  map[*semantic.Value]int
	params     []*semantic.Value
	freeVars   []*semantic.Value

	deps        map[*semantic.Value]originSet
	places      map[*semantic.Value]placeSet
	placeWrites map[Place]originSet

	// Per-round accumulators, rebuilt by compute.
	reads   placeSet
	writes  map[Place]originSet
	calls   []*CallFact
	returns map[int]originSet

	unknownReasons []string
	truncReasons   []string
	truncated      bool
}

func newFnWork(a *Analyzer, fn *semantic.Function) *fnWork {
	w := &fnWork{
		a:           a,
		fn:          fn,
		paramIndex:  make(map[*semantic.Value]int),
		freeIndex:   make(map[*semantic.Value]int),
		deps:        make(map[*semantic.Value]originSet),
		places:      make(map[*semantic.Value]placeSet),
		placeWrites: make(map[Place]originSet),
	}
	for _, v := range fn.Values {
		switch v.Kind {
		case semantic.ValueParam:
			w.paramIndex[v] = len(w.params)
			w.params = append(w.params, v)
		case semantic.ValueFreeVar:
			w.freeIndex[v] = len(w.freeVars)
			w.freeVars = append(w.freeVars, v)
		}
	}
	return w
}

// compute runs one fixpoint round for the function and returns its
// current summary.
func (w *fnWork) compute() *Summary {
	w.reads = newPlaceSet()
	w.writes = make(map[Place]originSet)
	w.calls = nil
	w.returns = make(map[int]originSet)

	for _, b := range w.fn.Blocks {
		for _, ins := range b.Instructions {
			w.instr(ins)
		}
	}

	resultCount := 0
	if w.fn.Signature != nil {
		resultCount = len(w.fn.Signature.Results)
	}
	returns := make([][]Origin, resultCount)
	for i := 0; i < resultCount; i++ {
		returns[i] = w.returns[i].sorted()
	}

	writes := make([]Write, 0, len(w.writes))
	for p, srcs := range w.writes {
		writes = append(writes, Write{Target: p, Sources: srcs.sorted()})
	}
	sort.Slice(writes, func(i, j int) bool { return placeLess(writes[i].Target, writes[j].Target) })

	reasons := append(append([]string(nil), w.unknownReasons...), w.truncReasons...)
	sort.Strings(reasons)
	reasons = dedupStrings(reasons)

	return &Summary{
		Function:  w.fn,
		Reads:     w.reads.sorted(),
		Writes:    writes,
		Calls:     w.calls,
		Returns:   returns,
		Unknown:   len(w.unknownReasons) > 0,
		Truncated: w.truncated || len(w.truncReasons) > 0,
		Reasons:   reasons,
	}
}

func placeLess(a, b Place) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.ID != b.ID {
		return a.ID < b.ID
	}
	return a.Index < b.Index
}

func dedupStrings(xs []string) []string {
	if len(xs) == 0 {
		return xs
	}
	out := xs[:1]
	for _, x := range xs[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}

// markUnknown records an unanalyzable effect on the function.
func (w *fnWork) markUnknown(reason string) {
	w.unknownReasons = appendUnique(w.unknownReasons, reason)
}

// markTruncated records a budget-related limitation. Truncation is
// reported separately from Unknown: the facts present are still
// correct may-facts, just incomplete.
func (w *fnWork) markTruncated(reason string) {
	w.truncated = true
	w.truncReasons = appendUnique(w.truncReasons, reason)
}

// ---------------------------------------------------------------------
// Per-instruction processing
// ---------------------------------------------------------------------

// readOps are instruction categories that observe memory through their
// first operand's place.
func readOp(op semantic.Op) bool {
	switch op {
	case semantic.OpLoad, semantic.OpIndex, semantic.OpSlice,
		semantic.OpRecv, semantic.OpTypeAssert:
		return true
	}
	return false
}

// placePreservingOps propagate the places of their operands to their
// outputs (the result still denotes the same memory location family).
func placePreserving(op semantic.Op) bool {
	switch op {
	case semantic.OpAddr, semantic.OpField, semantic.OpIndex,
		semantic.OpSlice, semantic.OpConvert, semantic.OpTypeAssert,
		semantic.OpPhi:
		return true
	}
	return false
}

func (w *fnWork) instr(ins *semantic.Instruction) {
	// Calls are handled entirely by w.call: their outputs carry callee
	// return facts, not the generic operand-union rule.
	if ins.Op == semantic.OpCall || ins.Op == semantic.OpGo || ins.Op == semantic.OpDefer {
		if call := w.a.prog.CallAt(ins); call != nil {
			w.call(ins, call)
			return
		}
		// A call-shaped instruction with no Call record is
		// unanalyzable.
		w.markUnknown("call instruction without call metadata at " + posString(ins.Position))
	}

	switch ins.Op {
	case semantic.OpStore:
		w.store(ins)
	case semantic.OpReturn:
		w.ret(ins)
	case semantic.OpOther:
		if ins.Detail == "MapUpdate" {
			w.mapUpdate(ins)
		}
	}

	if readOp(ins.Op) && len(ins.Operands) > 0 {
		w.readsThrough(ins.Operands[0])
	}

	if len(ins.Outputs) == 0 {
		return
	}

	deps := newOriginSet()
	for _, op := range ins.Operands {
		deps.union(w.depsOfValue(op))
	}

	// Reading instructions observe memory: fold in everything
	// previously written to the places they read (store→load flow,
	// including writes propagated from callees).
	if readOp(ins.Op) && len(ins.Operands) > 0 {
		for p := range w.placesOfValue(ins.Operands[0]) {
			deps.union(w.depsThroughPlace(p))
			if p.Kind == PlaceUnknown {
				deps.add(Origin{Kind: OriginUnknown})
			}
		}
	}

	places := newPlaceSet()
	switch {
	case ins.Op == semantic.OpAlloc:
		for _, out := range ins.Outputs {
			places.add(Place{Kind: PlaceLocal, ID: out.ID})
		}
	case placePreserving(ins.Op):
		for _, op := range ins.Operands {
			places.union(w.placesOfValue(op))
		}
	}

	for _, out := range ins.Outputs {
		w.addDeps(out, deps)
		w.addPlaces(out, places)
	}
}

// readsThrough records a read of every place the operand may denote
// and folds any values previously written to those places into the
// read's dependents via placeWrites (applied when the place is later
// used as an operand of a reading instruction — see readsThroughDeps).
func (w *fnWork) readsThrough(v *semantic.Value) {
	for p := range w.placesOfValue(v) {
		w.reads.add(p)
	}
}

// store handles OpStore: operands are [address, value].
func (w *fnWork) store(ins *semantic.Instruction) {
	if len(ins.Operands) < 2 {
		w.markUnknown("store with fewer than two operands at " + posString(ins.Position))
		return
	}
	addr, val := ins.Operands[0], ins.Operands[1]
	targets := w.placesOfValue(addr)
	if len(targets) == 0 {
		targets = newPlaceSet()
		targets.add(Place{Kind: PlaceUnknown})
	}
	sources := newOriginSet()
	sources.union(w.depsOfValue(val))
	for t := range targets {
		w.addWrite(t, sources)
		w.addPlaceWrite(t, sources)
	}
}

// mapUpdate handles ssa.MapUpdate, modeled as OpOther with
// Detail=="MapUpdate"; operands are [map, key, value].
func (w *fnWork) mapUpdate(ins *semantic.Instruction) {
	if len(ins.Operands) < 3 {
		w.markUnknown("map update with too few operands at " + posString(ins.Position))
		return
	}
	targets := w.placesOfValue(ins.Operands[0])
	if len(targets) == 0 {
		targets = newPlaceSet()
		targets.add(Place{Kind: PlaceUnknown})
	}
	sources := newOriginSet()
	sources.union(w.depsOfValue(ins.Operands[2]))
	for t := range targets {
		w.addWrite(t, sources)
		w.addPlaceWrite(t, sources)
	}
}

// ret records returned values by result index.
func (w *fnWork) ret(ins *semantic.Instruction) {
	for i, op := range ins.Operands {
		set := w.returns[i]
		if set == nil {
			set = newOriginSet()
			w.returns[i] = set
		}
		set.union(w.depsOfValue(op))
	}
}

// ---------------------------------------------------------------------
// Fact accessors with budget enforcement
// ---------------------------------------------------------------------

func (w *fnWork) addDeps(v *semantic.Value, deps originSet) {
	set := w.deps[v]
	if set == nil {
		set = newOriginSet()
		w.deps[v] = set
	}
	w.unionCapped(set, deps, "dependence set for "+v.ID)
}

func (w *fnWork) addPlaces(v *semantic.Value, places placeSet) {
	set := w.places[v]
	if set == nil {
		set = newPlaceSet()
		w.places[v] = set
	}
	for p := range places {
		set.add(p)
	}
	if w.opts().MaxOrigins >= 0 && len(set) > w.opts().MaxOrigins {
		w.markTruncated("place set for " + v.ID + " exceeds MaxOrigins")
	}
}

func (w *fnWork) addWrite(p Place, sources originSet) {
	set := w.writes[p]
	if set == nil {
		set = newOriginSet()
		w.writes[p] = set
	}
	w.unionCapped(set, sources, "write sources for place")
}

func (w *fnWork) addPlaceWrite(p Place, sources originSet) {
	set := w.placeWrites[p]
	if set == nil {
		set = newOriginSet()
		w.placeWrites[p] = set
	}
	w.unionCapped(set, sources, "place write set")
}

// unionCapped unions srcs into dst, enforcing MaxOrigins.
func (w *fnWork) unionCapped(dst, srcs originSet, what string) {
	max := w.opts().MaxOrigins
	for o := range srcs {
		if _, ok := dst[o]; ok {
			continue
		}
		if max >= 0 && len(dst) >= max {
			w.markTruncated(what + " exceeds MaxOrigins")
			return
		}
		dst.add(o)
	}
}

func (w *fnWork) opts() Options { return w.a.opts }

// ---------------------------------------------------------------------
// Origin / place computation
// ---------------------------------------------------------------------

// depsOfValue returns the Origins a value may depend on. For
// instruction-defined values this is the accumulated def-use fact;
// parameters, free variables, globals, and unresolved values seed
// their own origins.
func (w *fnWork) depsOfValue(v *semantic.Value) originSet {
	if v == nil {
		return newOriginSet()
	}
	switch v.Kind {
	case semantic.ValueParam:
		return originSet{Origin{Kind: OriginParam, Index: w.paramIndex[v]}: {}}
	case semantic.ValueFreeVar:
		return originSet{Origin{Kind: OriginFreeVar, Index: w.freeIndex[v]}: {}}
	case semantic.ValueGlobal:
		return originSet{Origin{Kind: OriginGlobal, ID: v.ID}: {}}
	case semantic.ValueConst, semantic.ValueFunction, semantic.ValueBuiltin:
		return newOriginSet()
	case semantic.ValueUnresolved:
		// Unresolved operands taint dependents conservatively but do
		// not by themselves mark the function unknown; only unresolved
		// call targets and unplaceable stores do.
		return originSet{Origin{Kind: OriginUnknown}: {}}
	case semantic.ValueInstr:
		if set := w.deps[v]; set != nil {
			return set
		}
		return newOriginSet()
	}
	return newOriginSet()
}

// placesOfValue returns the memory places a value may denote.
func (w *fnWork) placesOfValue(v *semantic.Value) placeSet {
	if v == nil {
		return newPlaceSet()
	}
	switch v.Kind {
	case semantic.ValueParam:
		return placeSet{Place{Kind: PlaceParam, Index: w.paramIndex[v]}: {}}
	case semantic.ValueFreeVar:
		return placeSet{Place{Kind: PlaceUnknown}: {}}
	case semantic.ValueGlobal:
		return placeSet{Place{Kind: PlaceGlobal, ID: v.ID}: {}}
	case semantic.ValueInstr:
		if set := w.places[v]; set != nil {
			return set
		}
		return newPlaceSet()
	}
	return newPlaceSet()
}

// depsThroughPlace returns the origins written to place p within this
// function (including writes propagated from callees), used to fold
// store→load flows into reading instructions.
func (w *fnWork) depsThroughPlace(p Place) originSet {
	if set := w.placeWrites[p]; set != nil {
		return set
	}
	return newOriginSet()
}

// ---------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------

// pureBuiltins are builtins whose only effect is their return value.
// Everything else (copy, delete, close, clear, panic, print, println,
// recover, ...) is treated as an unknown side effect.
var pureBuiltins = map[string]bool{
	"len": true, "cap": true, "real": true, "imag": true,
	"complex": true, "min": true, "max": true, "append": true,
	"new": true, "make": true,
	// ssa:wrapnilchk is the SSA nil-check wrapper intrinsic; it
	// returns its argument unchanged.
	"ssa:wrapnilchk": true,
}

// callArgValues returns the actual argument values for a call site in
// operand order, excluding the callee value (operand 0) for ordinary
// calls. For dynamic calls whose callees are all methods (interface
// invokes) operand 0 is the receiver and is kept.
func (w *fnWork) callArgValues(ins *semantic.Instruction, call *semantic.Call) []*semantic.Value {
	ops := ins.Operands
	if call.Kind == semantic.CallDefer && len(ops) > 1 {
		// ssa.Defer appends the synthetic deferStack operand last.
		last := ops[len(ops)-1]
		if last != nil && last.Name == "deferStack" {
			ops = ops[:len(ops)-1]
		}
	}
	if len(ops) == 0 {
		return nil
	}
	if call.Dynamic && allMethodCallees(call.Callees) {
		return ops
	}
	return ops[1:]
}

func allMethodCallees(callees []*semantic.Function) bool {
	if len(callees) == 0 {
		return false
	}
	for _, c := range callees {
		if c == nil || c.Receiver == nil {
			return false
		}
	}
	return true
}

// actualsFor aligns a call site's operands to callee's parameter list.
// It returns a slice of length len(paramValues(callee)) whose entries
// are the actual values (nil where no actual exists).
//
// Alignment rules, derived from go/ssa operand layout (operand 0 is
// the callee/receiver value, remaining operands are CallCommon.Args
// which include the receiver for static method calls):
//
//   - non-dynamic call: operands[1:] map to params in order. For
//     methods params[0] is the receiver and operands[1] is the
//     receiver actual, so indices line up directly.
//   - dynamic call to a method (interface invoke): operand 0 is the
//     receiver actual, so all operands map to params in order.
//   - dynamic call to a non-method (func value): operand 0 is the
//     function value itself; operands[1:] map to params.
func (a *Analyzer) actualsFor(ins *semantic.Instruction, call *semantic.Call, callee *semantic.Function) []*semantic.Value {
	params := a.paramValues(callee)
	if len(params) == 0 {
		return nil
	}
	ops := ins.Operands
	if call.Kind == semantic.CallDefer && len(ops) > 1 {
		last := ops[len(ops)-1]
		if last != nil && last.Name == "deferStack" {
			ops = ops[:len(ops)-1]
		}
	}
	if len(ops) == 0 {
		return make([]*semantic.Value, len(params))
	}
	var args []*semantic.Value
	if call.Dynamic && callee.Receiver != nil {
		args = ops
	} else {
		args = ops[1:]
	}
	out := make([]*semantic.Value, len(params))
	for i := range out {
		if i < len(args) {
			out[i] = args[i]
		}
	}
	return out
}

// paramValues returns the function's parameter values (including the
// receiver at index 0 for methods) in declaration order.
func (a *Analyzer) paramValues(fn *semantic.Function) []*semantic.Value {
	if fn == nil {
		return nil
	}
	if a.paramCache == nil {
		a.paramCache = make(map[*semantic.Function][]*semantic.Value)
	}
	if pv, ok := a.paramCache[fn]; ok {
		return pv
	}
	var pv []*semantic.Value
	for _, v := range fn.Values {
		if v.Kind == semantic.ValueParam {
			pv = append(pv, v)
		}
	}
	a.paramCache[fn] = pv
	return pv
}

// call processes one call-site instruction: it records a CallFact,
// propagates argument facts into callee parameters, merges callee
// return facts into the call outputs, and merges callee side effects
// into the caller's reads/writes.
func (w *fnWork) call(ins *semantic.Instruction, call *semantic.Call) {
	fact := &CallFact{
		Site:     ins,
		Position: ins.Position,
		Target:   call.Target,
		Dynamic:  call.Dynamic,
	}
	for _, c := range call.Callees {
		if c != nil {
			fact.Callees = append(fact.Callees, c.ID)
		}
	}
	sort.Strings(fact.Callees)
	fact.Callees = dedupStrings(fact.Callees)

	for _, arg := range w.callArgValues(ins, call) {
		fact.Args = append(fact.Args, w.depsOfValue(arg).sorted())
	}

	// Effective callee set: explicit Callees, plus a directly
	// referenced function value when the frontend recorded none
	// (e.g. CallGraphNone mode).
	callees := call.Callees
	if len(callees) == 0 && len(ins.Operands) > 0 {
		if fv := ins.Operands[0]; fv != nil && fv.Kind == semantic.ValueFunction && fv.Func != nil {
			callees = []*semantic.Function{fv.Func}
		}
	}

	resultCount := 0
	resultDeps := make(map[int]originSet)

	if call.Dynamic && len(callees) == 0 {
		fact.Unknown = true
		fact.Reason = "unresolved dynamic call target"
		w.markUnknown("unresolved dynamic call at " + posString(ins.Position))
		w.addUnknownToResults(ins, resultCount)
	} else if len(callees) == 0 {
		// Builtin or otherwise unmodeled call.
		w.builtinCall(ins, call, fact, resultDeps, &resultCount)
	} else {
		if call.Dynamic {
			fact.Reason = "dynamic dispatch: callee may-set may be incomplete"
		}
		for _, callee := range callees {
			if callee == nil {
				continue
			}
			resultCount = max(resultCount, resultCountOf(callee))
			w.propagateCall(ins, call, callee, fact, resultDeps)
		}
	}

	// Materialize per-result facts.
	fact.Results = make([][]Origin, resultCount)
	for i := 0; i < resultCount; i++ {
		fact.Results[i] = resultDeps[i].sorted()
	}

	// Assign result facts to the call's output values.
	w.assignCallOutputs(ins, resultDeps, resultCount)

	w.calls = append(w.calls, fact)
}

// resultCountOf returns the number of results a function signature
// declares.
func resultCountOf(fn *semantic.Function) int {
	if fn == nil || fn.Signature == nil {
		return 0
	}
	return len(fn.Signature.Results)
}

// propagateCall merges one callee's summary facts through the call
// site.
func (w *fnWork) propagateCall(ins *semantic.Instruction, call *semantic.Call, callee *semantic.Function, fact *CallFact, resultDeps map[int]originSet) {
	// Unanalyzable callees: external stubs and functions outside the
	// analysis budget.
	if len(callee.Blocks) == 0 {
		fact.Unknown = true
		if fact.Reason == "" {
			fact.Reason = "external or bodiless callee " + callee.ID
		} else {
			fact.Reason += "; external or bodiless callee " + callee.ID
		}
		w.markUnknown("call to external function " + callee.ID + " at " + posString(ins.Position))
		for i := 0; i < resultCountOf(callee); i++ {
			set := resultDeps[i]
			if set == nil {
				set = newOriginSet()
				resultDeps[i] = set
			}
			set.add(Origin{Kind: OriginUnknown})
		}
		return
	}
	if !w.a.analyzed[callee.ID] {
		fact.Unknown = true
		if fact.Reason == "" {
			fact.Reason = "callee " + callee.ID + " not analyzed (MaxFunctions)"
		} else {
			fact.Reason += "; callee " + callee.ID + " not analyzed (MaxFunctions)"
		}
		w.markUnknown("call to unanalyzed function " + callee.ID + " at " + posString(ins.Position))
		for i := 0; i < resultCountOf(callee); i++ {
			set := resultDeps[i]
			if set == nil {
				set = newOriginSet()
				resultDeps[i] = set
			}
			set.add(Origin{Kind: OriginUnknown})
		}
		return
	}

	cs := w.a.summaries[callee.ID]
	if cs == nil {
		// First round: no summary yet. Contributes nothing this
		// round; later rounds pick it up. Not an unknown.
		return
	}
	if cs.Truncated {
		if fact.Reason == "" {
			fact.Reason = "callee " + callee.ID + " summary truncated"
		} else {
			fact.Reason += "; callee " + callee.ID + " summary truncated"
		}
	}

	actuals := w.a.actualsFor(ins, call, callee)

	// Returns: map callee result origins through actual arguments.
	for j := 0; j < len(cs.Returns); j++ {
		set := resultDeps[j]
		if set == nil {
			set = newOriginSet()
			resultDeps[j] = set
		}
		for _, o := range cs.Returns[j] {
			w.mapOrigin(set, o, actuals)
		}
	}
	// Results beyond the computed returns (e.g. signature/results
	// mismatch) stay empty; conservative callers treat missing as
	// no facts rather than unknown.

	// Reads: callee place reads map onto caller places.
	for _, p := range cs.Reads {
		for q := range w.mapPlace(p, actuals) {
			w.reads.add(q)
		}
	}

	// Writes: callee writes map onto caller places; callee-local
	// places are not visible to the caller and are dropped.
	for _, wr := range cs.Writes {
		targets := w.mapPlace(wr.Target, actuals)
		for t := range targets {
			set := newOriginSet()
			for _, o := range wr.Sources {
				w.mapOriginInto(set, o, actuals)
			}
			w.addWrite(t, set)
			w.addPlaceWrite(t, set)
		}
	}
}

// mapOriginInto adds the caller-side image of callee origin o to set.
func (w *fnWork) mapOriginInto(set originSet, o Origin, actuals []*semantic.Value) {
	switch o.Kind {
	case OriginParam:
		if o.Index >= 0 && o.Index < len(actuals) && actuals[o.Index] != nil {
			set.union(w.depsOfValue(actuals[o.Index]))
		} else {
			set.add(Origin{Kind: OriginUnknown})
		}
	case OriginGlobal, OriginFreeVar, OriginUnknown:
		set.add(o)
	}
}

// mapOrigin is mapOriginInto applied through a capped union.
func (w *fnWork) mapOrigin(dst originSet, o Origin, actuals []*semantic.Value) {
	switch o.Kind {
	case OriginParam:
		if o.Index >= 0 && o.Index < len(actuals) && actuals[o.Index] != nil {
			w.unionCapped(dst, w.depsOfValue(actuals[o.Index]), "call result origins")
		} else {
			dst.add(Origin{Kind: OriginUnknown})
		}
	case OriginGlobal, OriginFreeVar, OriginUnknown:
		dst.add(o)
	}
}

// mapPlace maps a callee place onto caller places through the actual
// arguments. Callee-local places are dropped (not caller-visible);
// param places map onto the actual argument's places (or
// PlaceUnknown); global and unknown places pass through.
func (w *fnWork) mapPlace(p Place, actuals []*semantic.Value) placeSet {
	out := newPlaceSet()
	switch p.Kind {
	case PlaceGlobal, PlaceUnknown:
		out.add(p)
	case PlaceLocal:
		// Not visible to the caller.
	case PlaceParam:
		if p.Index >= 0 && p.Index < len(actuals) && actuals[p.Index] != nil {
			ps := w.placesOfValue(actuals[p.Index])
			if len(ps) == 0 {
				out.add(Place{Kind: PlaceUnknown})
			} else {
				out.union(ps)
			}
		} else {
			out.add(Place{Kind: PlaceUnknown})
		}
	}
	return out
}

// builtinCall handles call sites with no modeled callees and no
// dynamic flag: builtins and other unmodeled targets. resultDeps and
// resultCount are updated so the CallFact and call outputs carry the
// builtin's result facts.
func (w *fnWork) builtinCall(ins *semantic.Instruction, call *semantic.Call, fact *CallFact, resultDeps map[int]originSet, resultCount *int) {
	name := ""
	if len(ins.Operands) > 0 && ins.Operands[0] != nil {
		name = ins.Operands[0].Name
	}
	if name != "" && pureBuiltins[name] {
		// Pure builtin: results depend on the arguments.
		deps := newOriginSet()
		for _, op := range ins.Operands {
			deps.union(w.depsOfValue(op))
		}
		*resultCount = len(ins.Outputs)
		for i, out := range ins.Outputs {
			set := resultDeps[i]
			if set == nil {
				set = newOriginSet()
				resultDeps[i] = set
			}
			set.union(deps)
			w.addDeps(out, deps)
			if pointerLike(out.Type) {
				w.addPlaces(out, placeSet{Place{Kind: PlaceUnknown}: {}})
			}
		}
		return
	}
	fact.Unknown = true
	if name != "" {
		fact.Reason = "builtin " + name + " has unanalyzed side effects"
		w.markUnknown("call to builtin " + name + " at " + posString(ins.Position))
	} else {
		fact.Reason = "unmodeled call target at " + posString(ins.Position)
		w.markUnknown("unmodeled call at " + posString(ins.Position))
	}
	// Results (if any) are unknown.
	*resultCount = len(ins.Outputs)
	for i, out := range ins.Outputs {
		set := resultDeps[i]
		if set == nil {
			set = newOriginSet()
			resultDeps[i] = set
		}
		set.add(Origin{Kind: OriginUnknown})
		w.addDeps(out, set)
		if pointerLike(out.Type) {
			w.addPlaces(out, placeSet{Place{Kind: PlaceUnknown}: {}})
		}
	}
}

// pointerLike reports whether a type may denote a reference to memory
// whose contents the analysis cannot track through a call.
func pointerLike(t *semantic.Type) bool {
	if t == nil {
		return false
	}
	switch t.Kind {
	case semantic.TypePointer, semantic.TypeSlice, semantic.TypeMap,
		semantic.TypeChan, semantic.TypeFunc, semantic.TypeInterface,
		semantic.TypeTypeParam:
		return true
	}
	return false
}

// addUnknownToResults taints all call outputs with OriginUnknown for
// calls whose targets could not be resolved at all.
func (w *fnWork) addUnknownToResults(ins *semantic.Instruction, resultCount int) {
	set := newOriginSet()
	set.add(Origin{Kind: OriginUnknown})
	for _, out := range ins.Outputs {
		w.addDeps(out, set)
		if pointerLike(out.Type) {
			w.addPlaces(out, placeSet{Place{Kind: PlaceUnknown}: {}})
		}
	}
}

// assignCallOutputs writes the per-result origin sets onto the call
// instruction's output values.
func (w *fnWork) assignCallOutputs(ins *semantic.Instruction, resultDeps map[int]originSet, resultCount int) {
	outs := ins.Outputs
	if len(outs) == 0 {
		return
	}
	if len(outs) == 1 {
		deps := newOriginSet()
		if resultCount <= 1 {
			deps.union(resultDeps[0])
		} else {
			// Single tuple output for a multi-result call: union all
			// result facts (conservative).
			for i := 0; i < resultCount; i++ {
				deps.union(resultDeps[i])
			}
		}
		w.addDeps(outs[0], deps)
		if pointerLike(outs[0].Type) {
			w.addPlaces(outs[0], placeSet{Place{Kind: PlaceUnknown}: {}})
		}
		return
	}
	for j, out := range outs {
		if j < resultCount {
			w.addDeps(out, resultDeps[j])
		}
		if pointerLike(out.Type) {
			w.addPlaces(out, placeSet{Place{Kind: PlaceUnknown}: {}})
		}
	}
}

func posString(p semantic.Position) string {
	if p.File == "" {
		return "<unknown>"
	}
	return p.File
}
