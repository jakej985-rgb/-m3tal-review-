package statemachine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"github.com/jakej985-rgb/m3tal-review/internal/analysis/flow"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// This file implements the bounded evaluator: it explores reachable
// control-flow paths through the semantic program, firing contract
// events at bound call sites and checking guards, effects, and
// invariants on each path. Exploration is a may-analysis over
// (program point × machine configuration) with explicit backtracking;
// every budget is reported through Result.Budgets and findings are
// never silently promoted to proven when analysis was incomplete.

// Options controls evaluator budgets. Zero values select defaults.
type Options struct {
	// FlowOptions configures the underlying data-flow analysis used
	// for instance resolution and argument facts.
	FlowOptions flow.Options
	// MaxSteps bounds the total number of instructions explored across
	// all paths. Default 50000; negative means unlimited.
	MaxSteps int
	// MaxCallDepth bounds call-stack nesting during exploration.
	// Default 24; negative means unlimited.
	MaxCallDepth int
	// MaxInstances bounds distinct instance keys tracked per contract.
	// Overflow collapses into a shared "?" instance bucket and is
	// reported. Default 64; negative means unlimited.
	MaxInstances int
	// MaxFieldValue saturates integer field arithmetic so counter
	// loops terminate. Default 4096; negative means unlimited
	// (saturates at 1<<40).
	MaxFieldValue int64
	// MaxSequences bounds recorded event sequences per contract.
	// Default 256; negative means unlimited.
	MaxSequences int
	// MaxFindings bounds emitted findings per contract. Default 512;
	// negative means unlimited.
	MaxFindings int
}

const (
	defaultMaxSteps     = 50000
	defaultMaxCallDepth = 24
	defaultMaxInstances = 64
	defaultMaxSequences = 256
	defaultMaxFindings  = 512
)

func (o Options) withDefaults() Options {
	if o.MaxSteps == 0 {
		o.MaxSteps = defaultMaxSteps
	}
	if o.MaxCallDepth == 0 {
		o.MaxCallDepth = defaultMaxCallDepth
	}
	if o.MaxInstances == 0 {
		o.MaxInstances = defaultMaxInstances
	}
	if o.MaxFieldValue == 0 {
		o.MaxFieldValue = defaultMaxFieldValue
	}
	if o.MaxSequences == 0 {
		o.MaxSequences = defaultMaxSequences
	}
	if o.MaxFindings == 0 {
		o.MaxFindings = defaultMaxFindings
	}
	return o
}

// Sequence is one distinct event sequence observed during evaluation.
type Sequence struct {
	// ContractID identifies the contract.
	ContractID string
	// Instance is the machine instance key the sequence ran on.
	Instance string
	// Events are the applied event names in order.
	Events []string
}

// ContractResult summarizes one contract's evaluation.
type ContractResult struct {
	// ContractID identifies the contract.
	ContractID string
	// Evaluated reports whether path exploration ran for this
	// contract (at least one event function bound).
	Evaluated bool
	// States lists every declared state (sorted).
	States []string
	// StatesCovered lists states entered on at least one explored
	// path (sorted).
	StatesCovered []string
	// StatesUnreachable lists states that static transition-graph
	// analysis proves unreachable from the initial state (sorted).
	StatesUnreachable []string
	// StatesUncovered lists states reachable in the contract graph
	// but never entered during bounded evaluation (sorted).
	StatesUncovered []string
}

// Result is the outcome of Evaluate.
type Result struct {
	// Findings are contract violations in the shared analysis
	// contract, deterministically ordered.
	Findings []analysis.Finding
	// Diagnostics records binding problems, unsupported expressions,
	// unreachable states, and budget exhaustion — never silent.
	Diagnostics []analysis.Diagnostic
	// Sequences lists distinct applied event sequences observed, in
	// first-observed order.
	Sequences []Sequence
	// Contracts has one entry per input contract, in input order.
	Contracts []ContractResult
	// Budgets records the limits in effect and whether each was hit.
	Budgets []analysis.Budget
	// Truncated is true when any budget was exhausted.
	Truncated bool
	// Assumptions lists analysis caveats (external calls, unknown
	// guards, capped sequences) that qualify the findings.
	Assumptions []string
}

// Evaluate binds each contract to prog, runs the flow analysis once,
// and explores bounded control-flow paths per contract. prog must
// have been indexed (semantic frontends do this; Evaluate calls Index
// defensively).
func Evaluate(ctx context.Context, prog *semantic.Program, contracts []*Contract, opts Options) (*Result, error) {
	opts = opts.withDefaults()
	prog.Index()

	res := &Result{}
	flowAnalyzer := flow.NewAnalyzer(prog, opts.FlowOptions)
	flowResult := flowAnalyzer.Analyze(ctx)

	// Surface flow diagnostics (they are load/limit notes).
	for _, d := range flowResult.Diagnostics {
		res.Diagnostics = append(res.Diagnostics, analysis.Diagnostic{
			Severity: mapFlowSeverity(d.Severity),
			Category: analysis.DiagnosticCategory(d.Category),
			Message:  d.Message,
			Span:     spanFromPos(d.Position),
		})
	}
	if flowResult.Truncated {
		res.Truncated = true
		res.Budgets = append(res.Budgets, analysis.Budget{
			Name:      "flow-summaries",
			Truncated: true,
		})
	}

	var exs []*explorer
	for _, c := range contracts {
		if c == nil {
			continue
		}
		res.Diagnostics = append(res.Diagnostics, c.Check()...)
		bc := Bind(prog, c)
		res.Diagnostics = append(res.Diagnostics, bc.Diagnostics...)
		bc.data.maxField = opts.MaxFieldValue

		cr := ContractResult{ContractID: c.ID}
		for _, s := range c.States {
			cr.States = append(cr.States, s.Name)
		}
		sort.Strings(cr.States)
		cr.StatesUnreachable = unreachableStates(c)

		if len(bc.EventFuncs) == 0 || bc.data.initial == "" {
			cr.StatesUncovered = subtract(cr.States, nil)
			res.Contracts = append(res.Contracts, cr)
			continue
		}

		ex := newExplorer(prog, flowAnalyzer, bc, opts, res)
		ex.run(ctx)
		exs = append(exs, ex)
		cr.Evaluated = true
		cr.StatesCovered = ex.coveredStates()
		cr.StatesUncovered = subtract(cr.States, cr.StatesCovered)
		res.Contracts = append(res.Contracts, cr)

		// Per-contract diagnostics: uncovered states.
		for _, s := range cr.StatesUncovered {
			res.Diagnostics = append(res.Diagnostics, analysis.Diagnostic{
				Severity: analysis.DiagSeverityInfo,
				Category: analysis.DiagNote,
				Message: fmt.Sprintf("contract %q: state %q was never reached during bounded evaluation",
					c.ID, s),
			})
		}
		for _, s := range cr.StatesUnreachable {
			res.Diagnostics = append(res.Diagnostics, analysis.Diagnostic{
				Severity: analysis.DiagSeverityInfo,
				Category: analysis.DiagNote,
				Message: fmt.Sprintf("contract %q: state %q is unreachable in the transition graph",
					c.ID, s),
			})
		}
	}

	finalize(res, exs)
	return res, nil
}

// finalize merges per-contract explorer output into the result:
// findings with IDs and proven/potential status decided by overall
// completeness, sorted diagnostics, assumptions, and budgets.
func finalize(res *Result, exs []*explorer) {
	var findings []analysis.Finding
	assumptions := make(map[string]bool)
	for _, ex := range exs {
		for _, d := range ex.findings {
			f := d.finding
			// A finding may be proven only when its own path carried
			// no unknowns AND the whole evaluation completed within
			// budgets.
			if d.clean && !ex.truncated && !res.Truncated {
				f.Status = analysis.StatusProven
			}
			findings = append(findings, f)
		}
		for s := range ex.assumptions {
			assumptions[s] = true
		}
		if ex.seqOverflow > 0 {
			assumptions[fmt.Sprintf("event sequence recording truncated after %d sequences", ex.opts.MaxSequences)] = true
		}
	}
	findings = analysis.AssignFindingIDs(findings)
	analysis.SortFindings(findings)
	res.Findings = findings

	for s := range assumptions {
		res.Assumptions = append(res.Assumptions, s)
	}
	sort.Strings(res.Assumptions)

	analysis.SortDiagnostics(res.Diagnostics)
	// Sort and deduplicate budgets by name.
	sort.SliceStable(res.Budgets, func(i, j int) bool { return res.Budgets[i].Name < res.Budgets[j].Name })
	var budgets []analysis.Budget
	seen := make(map[string]bool)
	for _, b := range res.Budgets {
		key := fmt.Sprintf("%s|%d|%t", b.Name, b.Limit, b.Truncated)
		if seen[key] {
			continue
		}
		seen[key] = true
		budgets = append(budgets, b)
	}
	res.Budgets = budgets
}

func mapFlowSeverity(s semantic.Severity) analysis.DiagnosticSeverity {
	switch s {
	case semantic.SeverityError:
		return analysis.DiagSeverityError
	case semantic.SeverityWarning:
		return analysis.DiagSeverityWarning
	default:
		return analysis.DiagSeverityInfo
	}
}

func spanFromPos(p semantic.Position) analysis.Span {
	if !p.Valid() {
		return analysis.Span{}
	}
	return analysis.Span{
		File:        p.File,
		StartOffset: p.Offset,
		StartLine:   p.Line,
		StartColumn: p.Column,
		EndOffset:   p.EndOffset,
		EndLine:     p.EndLine,
		EndColumn:   p.EndColumn,
	}
}

// unreachableStates computes states not reachable from the initial
// state following the contract's transition graph, ignoring guards
// and program reachability.
func unreachableStates(c *Contract) []string {
	var initial string
	for _, s := range c.States {
		if s.Initial {
			initial = s.Name
		}
	}
	if initial == "" {
		return nil
	}
	reach := map[string]bool{initial: true}
	changed := true
	for changed {
		changed = false
		for i := range c.Transitions {
			t := &c.Transitions[i]
			if t.fromStates == nil {
				// "any": fires from every reachable state.
				if len(reach) > 0 && t.To != "" && !reach[t.To] {
					reach[t.To] = true
					changed = true
				}
				continue
			}
			fromReach := false
			for _, f := range t.fromStates {
				if reach[f] {
					fromReach = true
					break
				}
			}
			if fromReach && t.To != "" && !reach[t.To] {
				reach[t.To] = true
				changed = true
			}
		}
	}
	var out []string
	for _, s := range c.States {
		if !reach[s.Name] {
			out = append(out, s.Name)
		}
	}
	sort.Strings(out)
	return out
}

func subtract(all, covered []string) []string {
	set := make(map[string]bool, len(covered))
	for _, s := range covered {
		set[s] = true
	}
	var out []string
	for _, s := range all {
		if !set[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------
// Explorer
// ---------------------------------------------------------------------

// findingDraft pairs a finding with whether its path was free of
// unknowns (used for the proven/potential decision at finalize time).
type findingDraft struct {
	finding analysis.Finding
	clean   bool
}

type explorer struct {
	prog *semantic.Program
	flow *flow.Analyzer
	opts Options
	bc   *BoundContract
	res  *Result

	machines     map[string]*machine
	visited      map[string]bool
	steps        int
	truncated    bool
	truncReasons []string

	// stack records the active call chain for visited keys.
	stack []string

	// pathUnknown is true while the current path crossed an unknown
	// guard, dynamic call, or unanalyzed callee.
	pathUnknown bool

	findings       []findingDraft
	seenViolations map[string]bool
	sequences      map[string]bool
	seqOrder       []string
	seqOverflow    int
	covered        map[string]bool
	assumptions    map[string]bool
	externalNoted  map[string]bool
	budgetNoted    map[string]bool
	maxField       int64
}

func newExplorer(prog *semantic.Program, fa *flow.Analyzer, bc *BoundContract, opts Options, res *Result) *explorer {
	return &explorer{
		prog:           prog,
		flow:           fa,
		opts:           opts,
		bc:             bc,
		res:            res,
		machines:       make(map[string]*machine),
		visited:        make(map[string]bool),
		seenViolations: make(map[string]bool),
		sequences:      make(map[string]bool),
		covered:        make(map[string]bool),
		assumptions:    make(map[string]bool),
		externalNoted:  make(map[string]bool),
		budgetNoted:    make(map[string]bool),
		maxField:       opts.MaxFieldValue,
	}
}

// snapshot captures mutable exploration state for backtracking.
type snapshot struct {
	machines    map[string]*machine
	pathUnknown bool
}

func (e *explorer) snap() snapshot {
	m := make(map[string]*machine, len(e.machines))
	for k, v := range e.machines {
		m[k] = v.clone()
	}
	return snapshot{machines: m, pathUnknown: e.pathUnknown}
}

func (e *explorer) restore(s snapshot) {
	e.machines = s.machines
	e.pathUnknown = s.pathUnknown
}

// markTrunc records a budget exhaustion: once per budget name, as a
// Budget entry and a limit diagnostic.
func (e *explorer) markTrunc(reason string, budget string, used, limit int) {
	e.truncated = true
	e.res.Truncated = true
	if !containsStr(e.truncReasons, reason) {
		e.truncReasons = append(e.truncReasons, reason)
	}
	key := budget + "|" + reason
	if e.budgetNoted == nil {
		e.budgetNoted = make(map[string]bool)
	}
	if e.budgetNoted[key] {
		return
	}
	e.budgetNoted[key] = true
	e.res.Budgets = append(e.res.Budgets, analysis.Budget{
		Name:      budget,
		Limit:     limit,
		Used:      used,
		Truncated: true,
	})
	e.res.Diagnostics = append(e.res.Diagnostics, analysis.Diagnostic{
		Severity: analysis.DiagSeverityWarning,
		Category: analysis.DiagLimit,
		Message:  fmt.Sprintf("contract %q: %s", e.bc.Contract.ID, reason),
	})
}

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// run explores all entry functions.
func (e *explorer) run(ctx context.Context) {
	for _, entry := range e.bc.Entries {
		if err := ctx.Err(); err != nil {
			e.markTrunc("evaluation canceled: "+err.Error(), "context", 0, 0)
			return
		}
		if len(entry.Blocks) == 0 {
			continue
		}
		e.stack = append(e.stack, entry.ID)
		e.enter(entry, 0, func() {})
		e.stack = e.stack[:len(e.stack)-1]
		if e.truncated {
			break
		}
	}
	// Record budgets actually used.
	e.res.Budgets = append(e.res.Budgets,
		analysis.Budget{Name: "max-steps", Limit: e.opts.MaxSteps, Used: e.steps},
		analysis.Budget{Name: "max-call-depth", Limit: e.opts.MaxCallDepth},
	)
}

// enter explores all paths through fn, invoking k at each function
// return point (once per distinct path).
func (e *explorer) enter(fn *semantic.Function, depth int, k func()) {
	if len(fn.Blocks) == 0 {
		k()
		return
	}
	entry := entryBlock(fn)
	if entry < 0 {
		k()
		return
	}
	e.enterBlock(fn, entry, depth, k)
}

// entryBlock returns the index of the function's entry block: the
// first block without predecessors, else block 0.
func entryBlock(fn *semantic.Function) int {
	for i, b := range fn.Blocks {
		if len(b.Predecessors) == 0 {
			return i
		}
	}
	return 0
}

// machineSig serializes all machine states for visited keys.
func (e *explorer) machineSig() string {
	if len(e.machines) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(e.machines))
	for k := range e.machines {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i >= 32 {
			b.WriteString("|...")
			break
		}
		m := e.machines[k]
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m.state)
		fn := make([]string, 0, len(m.fields))
		for name, v := range m.fields {
			fn = append(fn, name+"="+v.String())
		}
		sort.Strings(fn)
		b.WriteByte('{')
		b.WriteString(strings.Join(fn, ","))
		b.WriteByte('}')
		b.WriteByte(';')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

// visitedKey builds the exploration visited key: program point +
// call stack + machine configuration.
func (e *explorer) visitedKey(fn *semantic.Function, bi int) string {
	var b strings.Builder
	b.WriteString(fn.ID)
	fmt.Fprintf(&b, "|%d|%d|", bi, len(e.stack))
	for _, s := range e.stack {
		b.WriteString(s)
		b.WriteByte(';')
	}
	b.WriteString(e.machineSig())
	return b.String()
}

// enterBlock explores a block entry, pruning already-visited
// configurations.
func (e *explorer) enterBlock(fn *semantic.Function, bi, depth int, k func()) {
	if bi < 0 || bi >= len(fn.Blocks) {
		k()
		return
	}
	key := e.visitedKey(fn, bi)
	if e.visited[key] {
		return
	}
	e.visited[key] = true
	e.walkSeq(fn, fn.Blocks[bi], 0, depth, k)
}

// walkSeq executes instructions from index ii in block b, forking at
// calls and at block end. k is invoked at each function return point
// reached along a path.
func (e *explorer) walkSeq(fn *semantic.Function, b *semantic.BasicBlock, ii, depth int, k func()) {
	for ; ii < len(b.Instructions); ii++ {
		if e.truncated {
			return
		}
		e.steps++
		if e.opts.MaxSteps >= 0 && e.steps > e.opts.MaxSteps {
			e.markTrunc("max-steps budget exhausted", "max-steps", e.steps, e.opts.MaxSteps)
			return
		}
		ins := b.Instructions[ii]
		if ins.Op != semantic.OpCall && ins.Op != semantic.OpGo && ins.Op != semantic.OpDefer {
			continue
		}
		call := e.prog.CallAt(ins)
		if call == nil {
			continue
		}
		e.processCall(fn, b, ii, ins, call, depth, k)
		return // continuations were handled inside processCall forks
	}
	// End of block: fork over successors.
	if len(b.Successors) == 0 {
		k()
		return
	}
	succs := append([]*semantic.BasicBlock(nil), b.Successors...)
	sort.Slice(succs, func(i, j int) bool { return succs[i].Index < succs[j].Index })
	snap := e.snap()
	for i, s := range succs {
		if e.truncated {
			return
		}
		if i > 0 {
			e.restore(snap)
		}
		// Find successor's index within fn.Blocks.
		e.enterBlock(fn, s.Index, depth, k)
	}
	e.restore(snap)
}

// processCall handles one call instruction: it forks per resolved
// callee, fires bound events, explores callee bodies, and continues
// the caller — all under per-alternative snapshots.
func (e *explorer) processCall(fn *semantic.Function, b *semantic.BasicBlock, ii int, ins *semantic.Instruction, call *semantic.Call, depth int, k func()) {
	callees := effectiveCallees(e.prog, ins, call)
	if len(callees) == 0 {
		if call.Dynamic {
			e.pathUnknown = true
			e.noteAssumption("dynamic call target could not be resolved; events inside it are unexplored")
		}
		e.walkSeq(fn, b, ii+1, depth, k)
		return
	}
	for _, callee := range callees {
		if e.truncated {
			return
		}
		snap := e.snap()
		events := e.bc.EventFuncs[callee.ID]
		if len(events) == 0 {
			e.callThen(fn, b, ii, ins, call, callee, depth, k)
		} else {
			for _, evName := range events {
				if e.truncated {
					break
				}
				snap2 := e.snap()
				e.fireEvent(evName, fn, ins, call, callee)
				e.callThen(fn, b, ii, ins, call, callee, depth, k)
				e.restore(snap2)
			}
		}
		e.restore(snap)
	}
}

// callThen explores the callee (when it has a body and depth allows)
// and then continues the caller at the instruction after the call.
func (e *explorer) callThen(fn *semantic.Function, b *semantic.BasicBlock, ii int, ins *semantic.Instruction, call *semantic.Call, callee *semantic.Function, depth int, k func()) {
	resume := func() { e.walkSeq(fn, b, ii+1, depth, k) }
	if len(callee.Blocks) == 0 {
		// External or bodiless callee: it cannot contain modeled
		// event calls, but its effects are unknown.
		e.noteExternal(callee)
		e.pathUnknown = true
		resume()
		return
	}
	if e.opts.MaxCallDepth >= 0 && depth+1 > e.opts.MaxCallDepth {
		e.markTrunc("max-call-depth budget exhausted", "max-call-depth", depth+1, e.opts.MaxCallDepth)
		resume()
		return
	}
	e.stack = append(e.stack, callee.ID+"@"+fmt.Sprint(ins.ID))
	e.enter(callee, depth+1, resume)
	e.stack = e.stack[:len(e.stack)-1]
}

// effectiveCallees returns the deduplicated callee may-set for a call
// site, including the ValueFunction fallback used by the flow
// analyzer.
func effectiveCallees(prog *semantic.Program, ins *semantic.Instruction, call *semantic.Call) []*semantic.Function {
	var out []*semantic.Function
	seen := make(map[string]bool)
	add := func(fn *semantic.Function) {
		if fn == nil || seen[fn.ID] {
			return
		}
		seen[fn.ID] = true
		out = append(out, fn)
	}
	for _, c := range call.Callees {
		add(c)
	}
	if len(out) == 0 && len(ins.Operands) > 0 {
		if fv := ins.Operands[0]; fv != nil && fv.Kind == semantic.ValueFunction && fv.Func != nil {
			add(fv.Func)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// noteExternal records that a path crossed an external/bodiless call.
func (e *explorer) noteExternal(callee *semantic.Function) {
	if e.externalNoted[callee.ID] {
		return
	}
	e.externalNoted[callee.ID] = true
	e.noteAssumption("call to external or bodiless function " + callee.ID + " has unknown effects")
}

func (e *explorer) noteAssumption(s string) {
	e.assumptions[s] = true
}

// fireEvent applies one contract event at a call site.
func (e *explorer) fireEvent(eventName string, caller *semantic.Function, ins *semantic.Instruction, call *semantic.Call, callee *semantic.Function) {
	c := e.bc.Contract
	argIdx := e.bc.SubjectArg[eventName]
	instKey := e.instanceKey(e.bc, ins, call, callee, argIdx, caller)
	if strings.Contains(instKey, "?") {
		// Instance identity could not be fully resolved: the machine
		// may merge distinct resources (or fail to merge aliases), so
		// any violation observed on this path must stay potential —
		// never proven.
		e.pathUnknown = true
		e.noteAssumption("resource instance identity unresolved at some event sites; related findings are potential, not proven")
	}

	m := e.machines[instKey]
	if m == nil {
		if e.opts.MaxInstances >= 0 && len(e.machines) >= e.opts.MaxInstances {
			// Collapse overflow instances into a shared bucket so the
			// analysis stays bounded; the merge is reported.
			e.markTrunc("max-instances budget exhausted", "max-instances", len(e.machines), e.opts.MaxInstances)
			instKey = "inst:overflow"
			m = e.machines[instKey]
			if m == nil {
				m = newMachine(e.bc, instKey)
				e.machines[instKey] = m
			}
		} else {
			m = newMachine(e.bc, instKey)
			e.machines[instKey] = m
			e.checkInitialInvariants(m, ins)
		}
	}
	// Build argument values for expressions.
	actuals := e.flow.ActualsFor(ins, call, callee)
	args := make([]Value, len(actuals))
	for i, a := range actuals {
		args[i] = valueFromSemantic(a)
	}
	input := EventInput{Name: eventName, Args: args, CalleeID: callee.ID}
	res := m.step(input, ins.Position)

	// Tag the last history entry with the callee for evidence.
	if n := len(m.history); n > 0 {
		m.history[n-1].CalleeID = callee.ID
	}

	e.covered[m.state] = true
	if n := len(m.history); n > 0 {
		e.covered[m.history[n-1].From] = true
	}
	if res.GuardUnknown {
		e.pathUnknown = true
	}
	e.recordSequence(c, instKey, m)
	if res.Violation != nil {
		e.reportViolation(c, m, instKey, ins, res.Violation)
	}
}

// checkInitialInvariants evaluates invariants in a fresh machine's
// initial state.
func (e *explorer) checkInitialInvariants(m *machine, pos *semantic.Instruction) {
	for i, inv := range m.contract.Invariants {
		ex := m.contract.invExprs[i]
		if ex == nil {
			continue
		}
		input := EventInput{}
		if toTri(ex.eval(m.envFor(input, ""))) == triFalse {
			msg := fmt.Sprintf("invariant %q is violated in initial state %q", inv.Expr, m.state)
			if inv.Message != "" {
				msg = inv.Message
			}
			v := &Violation{
				Kind:      ViolationInvariant,
				Event:     "(initial)",
				State:     m.state,
				Message:   msg,
				Invariant: inv.Expr,
			}
			var spos semantic.Position
			if pos != nil {
				spos = pos.Position
			}
			e.reportViolation(e.bc.Contract, m, m.instance, pos, v, spos)
			return
		}
	}
}

// recordSequence records the machine's applied-event sequence.
func (e *explorer) recordSequence(c *Contract, instKey string, m *machine) {
	var evs []string
	for _, h := range m.history {
		if h.Applied {
			evs = append(evs, h.Event)
		}
	}
	key := c.ID + "|" + instKey + "|" + strings.Join(evs, ">")
	if e.sequences[key] {
		return
	}
	if e.opts.MaxSequences >= 0 && len(e.seqOrder) >= e.opts.MaxSequences {
		e.seqOverflow++
		return
	}
	e.sequences[key] = true
	e.seqOrder = append(e.seqOrder, key)
	e.res.Sequences = append(e.res.Sequences, Sequence{
		ContractID: c.ID,
		Instance:   instKey,
		Events:     append([]string(nil), evs...),
	})
}

// reportViolation emits a finding for a machine violation, deduplicated
// by (contract, instance, kind, event, state, position).
func (e *explorer) reportViolation(c *Contract, m *machine, instKey string, ins *semantic.Instruction, v *Violation, positions ...semantic.Position) {
	var pos semantic.Position
	if len(positions) > 0 {
		pos = positions[0]
	} else if ins != nil {
		pos = ins.Position
	}
	dedupe := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%d|%s",
		c.ID, instKey, v.Kind, v.Event, v.State,
		pos.File, pos.Line, pos.Column, v.Invariant)
	if e.seenViolations[dedupe] {
		return
	}
	e.seenViolations[dedupe] = true
	if e.opts.MaxFindings >= 0 && len(e.findings) >= e.opts.MaxFindings {
		e.markTrunc("max-findings budget exhausted", "max-findings", len(e.findings), e.opts.MaxFindings)
		return
	}

	ruleID := "statemachine-illegal-transition"
	if v.Kind == ViolationInvariant {
		ruleID = "statemachine-invariant"
	}
	sev := "medium"
	if v.Kind == ViolationInvariant {
		sev = "high"
	}
	msg := fmt.Sprintf("contract %q: %s", c.ID, v.Message)
	if v.Kind == ViolationIllegalTransition {
		msg = fmt.Sprintf("contract %q: %s (instance %s)", c.ID, v.Message, instKey)
	}

	f := analysis.Finding{
		RuleID:     ruleID,
		RuleName:   "State machine contract violation",
		Analyzer:   "statemachine",
		Message:    msg,
		Category:   "review",
		Severity:   sev,
		Confidence: analysis.ConfidenceMedium,
		Status:     analysis.StatusPotential,
		Trace:      analysis.TraceStateTransition,
		Spans:      []analysis.Span{spanFromPos(pos)},
		Evidence:   e.evidenceFor(m, v, pos),
		Metadata: map[string]string{
			"contract": c.ID,
			"instance": instKey,
			"state":    v.State,
			"event":    v.Event,
		},
	}
	if v.Invariant != "" {
		f.Metadata["invariant"] = v.Invariant
	}
	e.findings = append(e.findings, findingDraft{finding: f, clean: !e.pathUnknown})
}

// evidenceFor builds the state-transition evidence trace from the
// machine's history plus a closing note for the violation.
func (e *explorer) evidenceFor(m *machine, v *Violation, pos semantic.Position) []analysis.EvidenceStep {
	var steps []analysis.EvidenceStep
	// Take the tail of the history: the path to the violation.
	start := 0
	const maxSteps = 24
	if len(m.history) > maxSteps {
		start = len(m.history) - maxSteps
		steps = append(steps, analysis.EvidenceStep{
			Kind: analysis.EvidenceNote,
			Note: fmt.Sprintf("... %d earlier transitions omitted", start),
		})
	}
	for _, h := range m.history[start:] {
		note := fmt.Sprintf("%s → %s on %q", h.From, h.To, h.Event)
		if !h.Applied {
			note = fmt.Sprintf("rejected: %s", h.Note)
		} else if h.GuardUnknown {
			note += " (guard unknown)"
		}
		step := analysis.EvidenceStep{
			Kind: analysis.EvidenceState,
			Note: note,
			Span: spanFromPos(h.Position),
		}
		if h.CalleeID != "" {
			step.Entity = &analysis.EntityRef{
				Kind: analysis.EntityFunction,
				ID:   h.CalleeID,
			}
		}
		steps = append(steps, step)
	}
	if v.Invariant != "" {
		steps = append(steps, analysis.EvidenceStep{
			Kind: analysis.EvidenceNote,
			Note: "violated invariant: " + v.Invariant,
			Span: spanFromPos(pos),
		})
	}
	if len(steps) == 0 {
		steps = append(steps, analysis.EvidenceStep{
			Kind: analysis.EvidenceNote,
			Note: v.Message,
			Span: spanFromPos(pos),
		})
	}
	return steps
}

// coveredStates returns the sorted set of states entered during
// exploration.
func (e *explorer) coveredStates() []string {
	out := make([]string, 0, len(e.covered))
	for s := range e.covered {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
