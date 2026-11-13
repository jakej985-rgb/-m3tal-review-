// Package concurrency implements shared-state and logical-atomicity
// analysis over the engine-neutral semantic program model
// (internal/semantic), consuming interprocedural summaries and place
// facts from internal/analysis/flow.
//
// The analyzer answers the question data-race detectors cannot: not
// "are these accesses synchronized" but "must these operations be
// atomic as a group". It models:
//
//   - goroutine creation (go statements become independent trace
//     roots), function calls (inlined with key translation),
//     defer (effects at function exit), and channels / sync.Once /
//     WaitGroup / sync.Map / atomics / unknown calls as explicit,
//     reported limitations rather than silent gaps;
//   - mutex critical sections for sync.Mutex and sync.RWMutex
//     (Lock/Unlock/TryLock, RLock/RUnlock/TryRLock), recognized by
//     package path + receiver type + method name. Lock ownership is
//     tracked as a held-set of section instances replayed over a
//     flattened event order; RWMutex read and write locks are
//     distinguished;
//   - shared-state identity via flow places (globals, parameters,
//     locals) with an origin-based fallback for values without place
//     facts, translated across call boundaries through actual
//     arguments;
//   - check-then-act violations: a read that may influence a branch
//     (a "check") followed by a write to compatible shared state
//     (an "act") where the two are not co-protected by a common
//     critical-section instance;
//   - lock-order inversions as potential deadlock evidence, and
//     unlock-of-unheld-lock events.
//
// Honesty guarantees:
//
//   - Every finding is StatusPotential: interleaving-based reasoning
//     is inherently may-analysis, and the flattened event order is an
//     approximation of control flow (documented in docs/concurrency.md).
//   - A violation is only reported when shared state AND a conflicting
//     check-then-act pattern are both established; every pair of
//     locks is never flagged.
//   - Unsupported primitives, unresolved calls, budgets, and
//     truncation are surfaced as diagnostics; nothing is silent.
//
// The Go binding lives at the edges: sync-primitive recognition and
// builtin effects are Go-specific; the core reasoning is
// language-neutral.
package concurrency

import (
	"context"
	"sort"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"github.com/jakej985-rgb/m3tal-review/internal/analysis/flow"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// Options controls analysis budgets. All fields are optional; zero
// values select the defaults documented on each field.
type Options struct {
	// Flow configures the underlying interprocedural data-flow
	// analyzer (summaries, place facts, value-flow queries).
	Flow flow.Options

	// MaxTraces bounds how many functions are replayed as trace
	// roots, in deterministic function-ID order. Default 512;
	// negative means unlimited.
	MaxTraces int
	// MaxEventsPerFunc bounds the flattened event list of one
	// function (including inlined callees). Default 4096;
	// non-positive means the default; negative means unlimited.
	MaxEventsPerFunc int
	// MaxAccessesPerTrace bounds the accesses recorded from one
	// trace before the rest are dropped (with a diagnostic).
	// Default 2048.
	MaxAccessesPerTrace int
	// MaxSections bounds reported critical sections. Default 512.
	MaxSections int
	// MaxFindings bounds emitted findings. Default 256.
	MaxFindings int
	// MaxFlowQueries bounds forward value-flow queries used for
	// check detection. Default 256.
	MaxFlowQueries int
	// MaxPairChecks bounds read/write pair examinations per trace.
	// Default 65536.
	MaxPairChecks int
	// MaxLockPairs bounds recorded lock-order observations.
	// Default 4096.
	MaxLockPairs int
	// MaxDiagnostics bounds emitted diagnostics. Default 256.
	MaxDiagnostics int
}

const (
	defaultMaxTraces           = 512
	defaultMaxEventsPerFunc    = 4096
	defaultMaxAccessesPerTrace = 2048
	defaultMaxSections         = 512
	defaultMaxFindings         = 256
	defaultMaxFlowQueries      = 256
	defaultMaxPairChecks       = 65536
	defaultMaxLockPairs        = 4096
	defaultMaxDiagnostics      = 256
)

func (o Options) withDefaults() Options {
	if o.MaxTraces == 0 {
		o.MaxTraces = defaultMaxTraces
	}
	if o.MaxEventsPerFunc <= 0 {
		o.MaxEventsPerFunc = defaultMaxEventsPerFunc
	}
	if o.MaxAccessesPerTrace <= 0 {
		o.MaxAccessesPerTrace = defaultMaxAccessesPerTrace
	}
	if o.MaxSections == 0 {
		o.MaxSections = defaultMaxSections
	}
	if o.MaxFindings == 0 {
		o.MaxFindings = defaultMaxFindings
	}
	if o.MaxFlowQueries == 0 {
		o.MaxFlowQueries = defaultMaxFlowQueries
	}
	if o.MaxPairChecks <= 0 {
		o.MaxPairChecks = defaultMaxPairChecks
	}
	if o.MaxLockPairs == 0 {
		o.MaxLockPairs = defaultMaxLockPairs
	}
	if o.MaxDiagnostics == 0 {
		o.MaxDiagnostics = defaultMaxDiagnostics
	}
	return o
}

// Analyzer runs concurrency analysis over a semantic.Program. It
// requires the flow analyzer's summaries and place facts; Analyze
// runs the flow analysis itself when needed.
type Analyzer struct {
	prog *semantic.Program
	opts Options

	flow    *flow.Analyzer
	flowRes *flow.Result

	// Lazily computed per-function flattened events.
	eventCache      map[string][]fev
	eventInProgress map[string]bool

	// Program-level counters for diagnostics.
	dynamicCalls int
	opaqueCalls  int
	atomicOps    int
	channelOps   int
	unsupported  map[string]bool
	notes        []string
	notesSeen    map[string]bool
	truncated    bool

	// Goroutine-context analysis.
	ctx       map[string]map[string]bool // function ID -> root IDs reaching it
	roots     []string                   // deterministic root function IDs
	goTargets map[string]bool            // function IDs started by go statements
	parents   map[string][]*semantic.Function
	parentsOK bool

	// Sharing tables.
	globalShared   map[string]bool
	paramSharedMap map[string]bool

	// Flow-query caches for check detection.
	flowCache      map[*semantic.Value]*flow.FlowResult
	branchCache    map[*semantic.Value]bool
	resultBranch   map[string]bool
	flowQueries    int
	flowQueriesHit bool

	// Lock-order observations: first-acquired -> second-acquired -> obs.
	lockOrder map[string]map[string]*lockOrderObs
	lockPairs int

	// Dedup of reported violations across traces.
	seenViolations map[string]bool

	// Lazily computed value indices and parameter-alias reps.
	valueIdx   map[*semantic.Function]*fnValueIndex
	paramAlias map[string][]int // function ID -> canonical param index per slot
}

// NewAnalyzer returns an Analyzer for prog.
func NewAnalyzer(prog *semantic.Program, opts Options) *Analyzer {
	prog.Index()
	return &Analyzer{
		prog:            prog,
		opts:            opts.withDefaults(),
		eventCache:      make(map[string][]fev),
		eventInProgress: make(map[string]bool),
		unsupported:     make(map[string]bool),
		notesSeen:       make(map[string]bool),
		ctx:             make(map[string]map[string]bool),
		goTargets:       make(map[string]bool),
		globalShared:    make(map[string]bool),
		paramSharedMap:  make(map[string]bool),
		flowCache:       make(map[*semantic.Value]*flow.FlowResult),
		branchCache:     make(map[*semantic.Value]bool),
		resultBranch:    make(map[string]bool),
		lockOrder:       make(map[string]map[string]*lockOrderObs),
		seenViolations:  make(map[string]bool),
		valueIdx:        make(map[*semantic.Function]*fnValueIndex),
		paramAlias:      make(map[string][]int),
	}
}

// Result is the outcome of Analyze.
type Result struct {
	// Findings are the detected concurrency findings, sorted
	// deterministically with IDs assigned.
	Findings []analysis.Finding
	// Diagnostics records analysis limitations: unsupported sync
	// primitives, unresolved calls, budget exhaustion, flow-analysis
	// problems.
	Diagnostics []analysis.Diagnostic
	// Shared lists shared-state keys established by the analysis.
	Shared []SharedState
	// Sections lists identified critical sections.
	Sections []CriticalSection
	// Truncated is true when any budget was exhausted.
	Truncated bool
}

// SharedState describes one shared-state key the analysis established
// as accessed under multiple goroutine contexts (or through captured
// state).
type SharedState struct {
	// Key is the canonical state-key rendering.
	Key string
	// Description is a human-readable summary of the key.
	Description string
	// Functions are the function IDs that accessed the state.
	Functions []string
	// Contexts are the goroutine-root IDs under which accesses occur.
	Contexts []string
}

// CriticalSection describes one lock acquisition region observed in a
// trace.
type CriticalSection struct {
	// ID is the section-instance identity (unique per call path).
	ID string
	// FunctionID is the function containing the acquire.
	FunctionID string
	// Lock describes the mutex key(s).
	Lock string
	// Try reports a conditional (TryLock/TryRLock) acquisition.
	Try bool
	// Acquire is the lock call's source position.
	Acquire semantic.Position
	// Release is the unlock position, or the zero Position when the
	// section runs to function exit (e.g. defer Unlock).
	Release semantic.Position
	// Accesses is the number of shared-state accesses attributed to
	// the section in the widest observed trace.
	Accesses int
}

// Analyze runs the flow analysis (if not already run by the caller
// through FlowResult — see note below) and then the concurrency
// analysis.
func (a *Analyzer) Analyze(ctx context.Context) *Result {
	res := &Result{}

	// 1. Underlying data-flow analysis.
	a.flow = flow.NewAnalyzer(a.prog, a.opts.Flow)
	a.flowRes = a.flow.Analyze(ctx)

	// 2. Goroutine-context and sharing analysis.
	a.buildContexts()
	a.computeParamAliases()
	a.computeGlobalSharing()

	// 3. Per-function traces.
	var findings []analysis.Finding
	shared := make(map[string]*SharedState)
	sections := make(map[string]*CriticalSection)
	var sectionOrder []string

	fns := a.traceableFunctions()
	for _, fn := range fns {
		if err := ctx.Err(); err != nil {
			a.note("analysis canceled: " + err.Error())
			break
		}
		tr := a.replay(fn)
		tr.markSharing(a)
		tr.markChecks(a)
		// Record shared states and sections.
		for i := range tr.accesses {
			acc := &tr.accesses[i]
			if !acc.shared {
				continue
			}
			for _, k := range acc.keys {
				sk := k.String()
				ss := shared[sk]
				if ss == nil {
					ss = &SharedState{Key: sk, Description: describeKey(k)}
					shared[sk] = ss
				}
				ss.Functions = appendUnique(ss.Functions, acc.owner.ID)
				for r := range a.ctx[fn.ID] {
					ss.Contexts = appendUnique(ss.Contexts, r)
				}
			}
		}
		for _, sec := range tr.sections {
			cs := sec.toCriticalSection()
			if cur, ok := sections[sec.id]; !ok {
				if len(sectionOrder) < a.opts.MaxSections {
					sectionOrder = append(sectionOrder, sec.id)
				}
				sections[sec.id] = cs
			} else {
				// Merge: keep the earliest release seen, max accesses.
				if cur.Release.File == "" && cs.Release.File != "" {
					cur.Release = cs.Release
				}
				if cs.Accesses > cur.Accesses {
					cur.Accesses = cs.Accesses
				}
			}
		}
		// Violations.
		findings = append(findings, a.violations(tr)...)
		findings = append(findings, a.unheldUnlockFindings(tr)...)
		// Lock-order observations.
		a.observeLockOrder(tr)
	}
	findings = append(findings, a.lockOrderFindings()...)

	// 4. Assemble result.
	res.Findings = dedupFindings(findings)
	analysis.AssignFindingIDs(res.Findings)
	analysis.SortFindings(res.Findings)
	if len(res.Findings) > a.opts.MaxFindings {
		res.Findings = res.Findings[:a.opts.MaxFindings]
		a.truncated = true
	}

	res.Shared = make([]SharedState, 0, len(shared))
	for _, ss := range shared {
		sort.Strings(ss.Functions)
		sort.Strings(ss.Contexts)
		res.Shared = append(res.Shared, *ss)
	}
	sort.Slice(res.Shared, func(i, j int) bool { return res.Shared[i].Key < res.Shared[j].Key })

	res.Sections = make([]CriticalSection, 0, len(sectionOrder))
	for _, id := range sectionOrder {
		res.Sections = append(res.Sections, *sections[id])
	}

	res.Diagnostics = a.diagnostics()
	analysis.SortDiagnostics(res.Diagnostics)
	if a.opts.MaxDiagnostics > 0 && len(res.Diagnostics) > a.opts.MaxDiagnostics {
		res.Diagnostics = res.Diagnostics[:a.opts.MaxDiagnostics]
	}
	res.Truncated = a.truncated
	return res
}

// traceableFunctions returns functions eligible as trace roots:
// every function with a body, in deterministic ID order, bounded by
// MaxTraces.
func (a *Analyzer) traceableFunctions() []*semantic.Function {
	var fns []*semantic.Function
	for _, pkg := range a.prog.Packages {
		for _, fn := range pkg.Functions {
			if len(fn.Blocks) == 0 {
				continue
			}
			fns = append(fns, fn)
		}
	}
	sort.Slice(fns, func(i, j int) bool { return fns[i].ID < fns[j].ID })
	if a.opts.MaxTraces >= 0 && len(fns) > a.opts.MaxTraces {
		fns = fns[:a.opts.MaxTraces]
		a.truncated = true
	}
	return fns
}

// ---------------------------------------------------------------------
// Goroutine contexts
// ---------------------------------------------------------------------

// buildContexts computes, for every function, the set of goroutine
// roots that may reach it. Roots are: the package-main main function
// (which also covers init functions, which run on the main
// goroutine), and every function invoked by a go statement. CallGo
// edges do not propagate context: a go statement creates a new
// goroutine whose accesses are concurrent with the spawner's.
func (a *Analyzer) buildContexts() {
	type edge struct {
		to   string
		kind semantic.CallKind
	}
	adj := make(map[string][]edge)
	var mainID string
	for _, pkg := range a.prog.Packages {
		for _, fn := range pkg.Functions {
			for _, call := range fn.Calls {
				for _, callee := range call.Callees {
					if callee == nil {
						continue
					}
					if call.Kind == semantic.CallGo {
						a.goTargets[callee.ID] = true
						continue
					}
					adj[fn.ID] = append(adj[fn.ID], edge{to: callee.ID, kind: call.Kind})
				}
			}
			if pkg.IsCommand && fn.Name == "main" && fn.Kind == semantic.FuncDecl {
				if mainID == "" || fn.ID < mainID {
					mainID = fn.ID
				}
			}
		}
	}

	// Roots: main plus every go-target. Init functions run on the
	// main goroutine before main; with no command main they are
	// roots of their own.
	var rootList []string
	seenRoot := make(map[string]bool)
	addRoot := func(id string) {
		if id == "" || seenRoot[id] {
			return
		}
		seenRoot[id] = true
		rootList = append(rootList, id)
		a.ctx[id] = map[string]bool{id: true}
	}
	addRoot(mainID)
	for id := range a.goTargets {
		addRoot(id)
	}
	// Init functions share the main goroutine.
	for _, pkg := range a.prog.Packages {
		for _, fn := range pkg.Functions {
			if fn.Kind != semantic.FuncInit {
				continue
			}
			if mainID != "" {
				if a.ctx[fn.ID] == nil {
					a.ctx[fn.ID] = make(map[string]bool)
				}
				a.ctx[fn.ID][mainID] = true
			} else {
				addRoot(fn.ID)
			}
		}
	}
	sort.Strings(rootList)
	a.roots = rootList

	// BFS/DFS from each root over non-go edges.
	for _, r := range rootList {
		stack := []string{r}
		visited := map[string]bool{r: true}
		for len(stack) > 0 {
			cur := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for _, e := range adj[cur] {
				if visited[e.to] {
					continue
				}
				visited[e.to] = true
				if a.ctx[e.to] == nil {
					a.ctx[e.to] = make(map[string]bool)
				}
				a.ctx[e.to][r] = true
				stack = append(stack, e.to)
			}
		}
	}
}

// computeGlobalSharing marks global places accessed under two or more
// distinct goroutine roots as shared, using flow summaries.
func (a *Analyzer) computeGlobalSharing() {
	users := make(map[string]map[string]bool) // global value ID -> root IDs
	for _, s := range a.flowRes.Summaries {
		fnCtx := a.ctx[s.Function.ID]
		consider := func(p flow.Place) {
			if p.Kind != flow.PlaceGlobal {
				return
			}
			m := users[p.ID]
			if m == nil {
				m = make(map[string]bool)
				users[p.ID] = m
			}
			for r := range fnCtx {
				m[r] = true
			}
		}
		for _, p := range s.Reads {
			consider(p)
		}
		for _, w := range s.Writes {
			consider(w.Target)
		}
	}
	for id, roots := range users {
		if len(roots) >= 2 {
			a.globalShared[id] = true
		}
	}

	// Flow summaries treat recognized atomic/sync accesses as opaque
	// external calls, so also harvest global places directly from the
	// extracted access events. Events inlined into a caller keep their
	// callee owner, so attribute contexts by event owner.
	for _, fn := range a.traceableFunctions() {
		for _, ev := range a.flatEvents(fn) {
			if ev.kind != fevRead && ev.kind != fevWrite {
				continue
			}
			ownerCtx := a.ctx[ev.owner.ID]
			if len(ownerCtx) == 0 {
				continue
			}
			for _, k := range ev.keys {
				for _, at := range k.places {
					if at.kind != atomPlaceGlobal {
						continue
					}
					m := users[at.id]
					if m == nil {
						m = make(map[string]bool)
						users[at.id] = m
					}
					for r := range ownerCtx {
						m[r] = true
					}
				}
			}
		}
	}
	for id, roots := range users {
		if len(roots) >= 2 {
			a.globalShared[id] = true
		}
	}
}

// paramShared reports whether function fn's parameter storage may be
// accessed concurrently: either fn runs under multiple goroutine
// contexts, or it is itself the target of a go statement.
func (a *Analyzer) paramShared(fn *semantic.Function) bool {
	if fn == nil {
		return false
	}
	if v, ok := a.paramSharedMap[fn.ID]; ok {
		return v
	}
	shared := a.goTargets[fn.ID] || len(a.ctx[fn.ID]) >= 2
	a.paramSharedMap[fn.ID] = shared
	return shared
}

// parentsOf returns candidate parent functions of fn: functions
// containing an instruction that references fn as a function value
// (e.g. the MakeClosure that creates it).
func (a *Analyzer) parentsOf(fn *semantic.Function) []*semantic.Function {
	if !a.parentsOK {
		a.parentsOK = true
		a.parents = make(map[string][]*semantic.Function)
		seen := make(map[string]map[string]bool)
		for _, pkg := range a.prog.Packages {
			for _, f := range pkg.Functions {
				for _, b := range f.Blocks {
					for _, ins := range b.Instructions {
						for _, op := range ins.Operands {
							if op == nil || op.Kind != semantic.ValueFunction || op.Func == nil {
								continue
							}
							target := op.Func.ID
							if seen[target] == nil {
								seen[target] = make(map[string]bool)
							}
							if !seen[target][f.ID] {
								seen[target][f.ID] = true
								a.parents[target] = append(a.parents[target], f)
							}
						}
					}
				}
			}
		}
		for id := range a.parents {
			sort.Slice(a.parents[id], func(i, j int) bool { return a.parents[id][i].ID < a.parents[id][j].ID })
		}
	}
	return a.parents[fn.ID]
}

// freevarShared reports whether state captured by fn's free variables
// may be shared: true when a candidate parent function runs under a
// different goroutine context than fn.
func (a *Analyzer) freevarShared(fn *semantic.Function) bool {
	if fn == nil {
		return false
	}
	fctx := a.ctx[fn.ID]
	for _, p := range a.parentsOf(fn) {
		pctx := a.ctx[p.ID]
		if !ctxEqual(fctx, pctx) {
			return true
		}
	}
	return false
}

func ctxEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func appendUnique(xs []string, x string) []string {
	for _, e := range xs {
		if e == x {
			return xs
		}
	}
	return append(xs, x)
}

// note records an analysis note for diagnostics (deduplicated).
func (a *Analyzer) note(msg string) {
	if a.notesSeen[msg] {
		return
	}
	a.notesSeen[msg] = true
	a.notes = append(a.notes, msg)
}

func (a *Analyzer) noteUnsupported(callee *semantic.Function) {
	name := callee.ID
	if callee.Package != nil {
		name = callee.Package.Path + "." + callee.Name
	}
	a.unsupported[name] = true
}
