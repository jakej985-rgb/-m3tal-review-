package flow

import "github.com/jakej985-rgb/m3tal-review/internal/semantic"

// callRef records one call edge from a caller function to a callee,
// used by the Flow query to cross function boundaries in both
// directions (arguments into parameters, returns into results).
type callRef struct {
	caller *semantic.Function
	site   *semantic.Instruction
	call   *semantic.Call
}

// FlowEvent is one step in an interprocedural value-flow trace. It
// identifies a value, where it was observed, and how the value passed
// between functions.
type FlowEvent struct {
	// ValueID is the stable semantic value ID.
	ValueID string
	// FunctionID is the function that scopes the value (empty for
	// shared values such as globals and function references).
	FunctionID string
	// Op is the instruction category active at this step, or
	// OpInvalid for the seed.
	Op semantic.Op
	// Detail carries the frontend-specific instruction name when the
	// model provides one.
	Detail string
	// Position is the source position of the observing instruction.
	Position semantic.Position
	// Via describes how the value was reached from its predecessor:
	// "seed", "def-use", "call-arg", "return", or "call-result".
	Via string
	// FromValueID is the predecessor value's ID (empty for the seed).
	FromValueID string
}

// FlowResult is the outcome of a forward value-flow query.
type FlowResult struct {
	// SeedID is the ID of the value the query started from.
	SeedID string
	// Events lists every reached value in breadth-first discovery
	// order; Events[0] is always the seed.
	Events []FlowEvent
	// Truncated is true when MaxFlowEvents stopped the search before
	// all reachable values were visited.
	Truncated bool

	parents map[string]string     // valueID -> predecessor valueID ("" for seed)
	byValue map[string]*FlowEvent // valueID -> discovery event
}

// Trace reconstructs the chain of events that first reached the value
// toID, ordered from the seed to that value. It returns nil when toID
// was not reached. The returned slice is freshly allocated.
func (r *FlowResult) Trace(toID string) []FlowEvent {
	if r == nil || toID == "" {
		return nil
	}
	if _, ok := r.parents[toID]; !ok {
		return nil
	}
	var rev []FlowEvent
	for cur := toID; cur != ""; {
		ev := r.byValue[cur]
		if ev == nil {
			break
		}
		rev = append(rev, *ev)
		cur = r.parents[cur]
	}
	out := make([]FlowEvent, len(rev))
	for i, ev := range rev {
		out[len(rev)-1-i] = ev
	}
	return out
}

// flowWork carries the BFS state for one Flow query.
type flowWork struct {
	a       *Analyzer
	res     *FlowResult
	visited map[*semantic.Value]bool
	queue   []*semantic.Value
}

// Flow computes forward interprocedural value reachability from seed:
// within functions through def-use edges (operands to instruction
// outputs, including phi merges and branch joins), across call
// boundaries through argument→parameter and return→call-result edges,
// using the model's resolved callee may-sets (Call.Callees).
//
// Flow is a may-reachability over value identities. It does not model
// heap flow (values written through pointers are not re-materialized
// at loads) and it only walks forward: to explain where a value came
// from, seed the query at an earlier value or inspect Summary facts.
func (a *Analyzer) Flow(seed *semantic.Value) *FlowResult {
	res := &FlowResult{
		SeedID:  "",
		parents: make(map[string]string),
		byValue: make(map[string]*FlowEvent),
	}
	if seed == nil {
		return res
	}
	res.SeedID = seed.ID
	a.ensureIndexes()

	w := &flowWork{
		a:       a,
		res:     res,
		visited: make(map[*semantic.Value]bool),
	}
	w.emit(seed, nil, "seed", "")
	w.visited[seed] = true
	w.queue = append(w.queue, seed)

	for len(w.queue) > 0 {
		if a.opts.MaxFlowEvents >= 0 && len(res.Events) >= a.opts.MaxFlowEvents {
			res.Truncated = true
			break
		}
		v := w.queue[0]
		w.queue = w.queue[1:]
		for _, use := range a.prog.Uses(v) {
			if use == nil {
				continue
			}
			if call := a.prog.CallAt(use); call != nil {
				w.throughCall(v, use, call)
				continue
			}
			if use.Op == semantic.OpReturn {
				w.throughReturn(v, use)
				continue
			}
			for _, out := range use.Outputs {
				w.emit(out, use, "def-use", v.ID)
			}
		}
	}
	return res
}

// emit records a newly reached value.
func (w *flowWork) emit(to *semantic.Value, instr *semantic.Instruction, via, fromID string) {
	if to == nil || w.visited[to] {
		return
	}
	w.visited[to] = true
	op := semantic.OpInvalid
	detail := ""
	var pos semantic.Position
	if instr != nil {
		op = instr.Op
		detail = instr.Detail
		pos = instr.Position
	}
	fnID := ""
	if to.Owner != nil {
		fnID = to.Owner.ID
	}
	w.res.Events = append(w.res.Events, FlowEvent{
		ValueID:     to.ID,
		FunctionID:  fnID,
		Op:          op,
		Detail:      detail,
		Position:    pos,
		Via:         via,
		FromValueID: fromID,
	})
	ev := &w.res.Events[len(w.res.Events)-1]
	w.res.parents[to.ID] = fromID
	w.res.byValue[to.ID] = ev
	w.queue = append(w.queue, to)
}

// throughCall propagates a value used at a call site into each
// resolved callee's corresponding parameter.
func (w *flowWork) throughCall(v *semantic.Value, site *semantic.Instruction, call *semantic.Call) {
	callees := call.Callees
	if len(callees) == 0 && len(site.Operands) > 0 {
		if fv := site.Operands[0]; fv != nil && fv.Kind == semantic.ValueFunction && fv.Func != nil {
			callees = []*semantic.Function{fv.Func}
		}
	}
	for _, callee := range callees {
		if callee == nil {
			continue
		}
		params := w.a.paramValues(callee)
		if len(params) == 0 {
			continue
		}
		actuals := w.a.actualsFor(site, call, callee)
		for i, actual := range actuals {
			if actual == v && i < len(params) {
				w.emit(params[i], site, "call-arg", v.ID)
			}
		}
	}
}

// throughReturn propagates a value used as a return operand back out
// to every call site that invokes the owning function, landing on the
// corresponding call result.
func (w *flowWork) throughReturn(v *semantic.Value, ret *semantic.Instruction) {
	owner := w.a.instructionOwner(ret)
	if owner == nil {
		return
	}
	// Result index = position of v among the return operands.
	resultIdx := -1
	for i, op := range ret.Operands {
		if op == v {
			resultIdx = i
			break
		}
	}
	if resultIdx < 0 {
		return
	}
	for _, ref := range w.a.callersOf(owner) {
		outs := ref.site.Outputs
		if len(outs) == 0 {
			continue
		}
		// Single tuple output for multi-result calls maps every result
		// index onto output 0.
		out := outs[0]
		if len(outs) > 1 && resultIdx < len(outs) {
			out = outs[resultIdx]
		}
		w.emit(out, ref.site, "call-result", v.ID)
	}
}

// ensureIndexes builds the caller and instruction-owner indices used
// by Flow.
func (a *Analyzer) ensureIndexes() {
	if a.ownerIndex {
		return
	}
	a.ownerIndex = true
	a.instrOwner = make(map[*semantic.Instruction]*semantic.Function)
	for _, pkg := range a.prog.Packages {
		for _, fn := range pkg.Functions {
			for _, b := range fn.Blocks {
				for _, ins := range b.Instructions {
					a.instrOwner[ins] = fn
				}
			}
			for _, c := range fn.Calls {
				for _, callee := range c.Callees {
					if callee != nil {
						a.callers[callee.ID] = append(a.callers[callee.ID], &callRef{caller: fn, site: c.Site, call: c})
					}
				}
			}
		}
	}
}

// callersOf returns the recorded call sites invoking fn.
func (a *Analyzer) callersOf(fn *semantic.Function) []*callRef {
	a.ensureIndexes()
	return a.callers[fn.ID]
}

// instructionOwner returns the function containing instr, or nil.
func (a *Analyzer) instructionOwner(instr *semantic.Instruction) *semantic.Function {
	a.ensureIndexes()
	return a.instrOwner[instr]
}
