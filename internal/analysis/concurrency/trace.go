package concurrency

import (
	"sort"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis/flow"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// accessKind classifies a recorded shared-state access.
type accessKind int

const (
	accRead accessKind = iota
	accWrite
)

// traceAccess is one shared-state access observed while replaying a
// function's flattened events, annotated with the critical-section
// instances held at that point.
type traceAccess struct {
	kind   accessKind
	keys   []stateKey
	instr  *semantic.Instruction
	owner  *semantic.Function
	held   []string // sorted section-instance IDs held at the access
	shared bool
	check  bool
}

// sectionInst is one critical-section instance: a single lock
// acquisition and (where observed) its matching release.
type sectionInst struct {
	id        string
	owner     *semantic.Function
	acquire   *semantic.Instruction
	release   *semantic.Instruction
	lockKeys  []string // canonical mutex key strings
	try       bool
	accesses  int
	traceFnID string
}

func (s *sectionInst) toCriticalSection() *CriticalSection {
	cs := &CriticalSection{
		ID:         s.id,
		FunctionID: s.owner.ID,
		Lock:       joinStrings(s.lockKeys),
		Try:        s.try,
		Accesses:   s.accesses,
	}
	if s.acquire != nil {
		cs.Acquire = s.acquire.Position
	}
	if s.release != nil {
		cs.Release = s.release.Position
	}
	return cs
}

// unheldUnlock records a release for a mutex slot that was not held
// in the replayed event order.
type unheldUnlock struct {
	instr *semantic.Instruction
	owner *semantic.Function
	keys  []stateKey
}

// lockAcq records one lock acquisition in trace order for lock-order
// analysis.
type lockAcq struct {
	base   string // mutex identity ignoring read/write lock kind
	instID string
	instr  *semantic.Instruction
	owner  *semantic.Function
}

// lockOrderObs is one observed acquisition order between two distinct
// mutexes.
type lockOrderObs struct {
	traceFnID string
	instr     *semantic.Instruction
	owner     *semantic.Function
	second    string // the later-acquired mutex base key
}

// traceResult is the replay outcome for one function.
type traceResult struct {
	fn              *semantic.Function
	accesses        []traceAccess
	sections        map[string]*sectionInst
	sectionOrder    []*sectionInst
	lockSeq         []lockAcq
	unheld          []unheldUnlock
	sawDynamic      bool
	accessTruncated bool
}

// replay interprets a function's flattened events, tracking held
// lock-section instances and recording shared-state accesses with
// their guarding sections.
func (a *Analyzer) replay(fn *semantic.Function) *traceResult {
	tr := &traceResult{
		fn:       fn,
		sections: make(map[string]*sectionInst),
	}
	events := a.flatEvents(fn)
	held := make(map[string]string) // lock slot -> section instance ID

	flushHeld := func() {}
	_ = flushHeld

	for _, ev := range events {
		switch ev.kind {
		case fevAcquire:
			instID := sectionID(ev)
			sec := tr.sections[instID]
			if sec == nil {
				sec = &sectionInst{
					id:        instID,
					owner:     ev.owner,
					acquire:   ev.instr,
					try:       ev.try,
					traceFnID: fn.ID,
				}
				for _, k := range ev.keys {
					sec.lockKeys = appendUnique(sec.lockKeys, k.String())
				}
				sort.Strings(sec.lockKeys)
				tr.sections[instID] = sec
				tr.sectionOrder = append(tr.sectionOrder, sec)
			}
			lk := "w"
			if ev.lock == lockRead {
				lk = "r"
			}
			for _, k := range ev.keys {
				held[k.String()+"|"+lk] = instID
			}
			if len(ev.keys) == 0 {
				// Unidentifiable mutex: recorded as a note at
				// flatten time; no section is tracked.
			}
			tr.lockSeq = append(tr.lockSeq, lockAcq{
				base:   joinStrings(keyStrings(ev.keys)),
				instID: instID,
				instr:  ev.instr,
				owner:  ev.owner,
			})

		case fevRelease:
			lk := "w"
			if ev.lock == lockRead {
				lk = "r"
			}
			for _, k := range ev.keys {
				slot := k.String() + "|" + lk
				instID, ok := held[slot]
				if !ok {
					tr.unheld = append(tr.unheld, unheldUnlock{instr: ev.instr, owner: ev.owner, keys: ev.keys})
					continue
				}
				delete(held, slot)
				if sec := tr.sections[instID]; sec != nil && sec.release == nil {
					sec.release = ev.instr
				}
			}
			if len(ev.keys) == 0 {
				tr.unheld = append(tr.unheld, unheldUnlock{instr: ev.instr, owner: ev.owner, keys: ev.keys})
			}

		case fevRead, fevWrite:
			if len(tr.accesses) >= a.opts.MaxAccessesPerTrace {
				tr.accessTruncated = true
				continue
			}
			kind := accRead
			if ev.kind == fevWrite {
				kind = accWrite
			}
			// Collect the distinct section instances currently held.
			instSet := make(map[string]bool, len(held))
			for _, id := range held {
				instSet[id] = true
			}
			heldIDs := make([]string, 0, len(instSet))
			for id := range instSet {
				heldIDs = append(heldIDs, id)
			}
			sort.Strings(heldIDs)
			tr.accesses = append(tr.accesses, traceAccess{
				kind:  kind,
				keys:  ev.keys,
				instr: ev.instr,
				owner: ev.owner,
				held:  heldIDs,
			})
			// Attribute the access to each held section for reporting.
			for _, id := range heldIDs {
				if sec := tr.sections[id]; sec != nil {
					sec.accesses++
				}
			}

		case fevNote:
			if ev.note == "unresolved dynamic call target" {
				tr.sawDynamic = true
			}
		}
	}
	return tr
}

// sectionID computes the unique section-instance identity for an
// acquire event: the call path plus the owning function and
// instruction.
func sectionID(ev fev) string {
	return ev.path + ev.owner.ID + "#" + itoa(ev.instr.ID)
}

func keyStrings(keys []stateKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.String())
	}
	sort.Strings(out)
	return out
}

func joinStrings(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	out := xs[0]
	for _, x := range xs[1:] {
		out += "," + x
	}
	return out
}

// ---------------------------------------------------------------------
// Sharing and check marking
// ---------------------------------------------------------------------

// markSharing sets acc.shared for every access in the trace.
func (tr *traceResult) markSharing(a *Analyzer) {
	for i := range tr.accesses {
		tr.accesses[i].shared = tr.accesses[i].keysShared(a, tr.fn)
	}
}

// keysShared reports whether any key denotes state that may be
// accessed concurrently.
func (acc *traceAccess) keysShared(a *Analyzer, traceRoot *semantic.Function) bool {
	_ = traceRoot
	for _, k := range acc.keys {
		if k.isPlaceKey() {
			for _, at := range k.places {
				if placeAtomShared(a, at) {
					return true
				}
			}
			continue
		}
		for _, at := range k.origins {
			if originAtomShared(a, at) {
				return true
			}
		}
	}
	return false
}

func placeAtomShared(a *Analyzer, at atom) bool {
	switch at.kind {
	case atomPlaceGlobal:
		return a.globalShared[at.id]
	case atomPlaceParam:
		fn := a.prog.Function(at.scope)
		return a.paramShared(fn)
	case atomPlaceLocal, atomPlaceUnknown:
		return false
	}
	return false
}

func originAtomShared(a *Analyzer, at atom) bool {
	switch at.kind {
	case atomOriginGlobal:
		return a.globalShared[at.id]
	case atomOriginParam:
		fn := a.prog.Function(at.scope)
		return a.paramShared(fn)
	case atomOriginFreeVar:
		fn := a.prog.Function(at.scope)
		return a.freevarShared(fn)
	case atomOriginUnknown:
		return false
	}
	return false
}

// markChecks sets acc.check for shared read accesses whose value may
// influence a branch (directly through value flow, or indirectly
// through a return value used in a branch by a caller).
func (tr *traceResult) markChecks(a *Analyzer) {
	for i := range tr.accesses {
		acc := &tr.accesses[i]
		if !acc.shared || acc.kind != accRead {
			continue
		}
		acc.check = a.isCheck(acc)
	}
}

// isCheck reports whether the read access's result may influence a
// branch condition.
func (a *Analyzer) isCheck(acc *traceAccess) bool {
	if acc.instr == nil || len(acc.instr.Outputs) == 0 {
		return false
	}
	// Loads that fetch pointer/reference values are address plumbing,
	// not checks of shared data contents.
	if pointerLikeOutput(acc.instr) {
		return false
	}
	// Direct: forward value flow reaches a branch operand.
	for _, out := range acc.instr.Outputs {
		if a.flowReachesBranch(out) {
			return true
		}
	}
	// Indirect: the read may influence the owner's return value, and
	// some caller branches on the call result.
	owner := acc.owner
	if owner == nil {
		return false
	}
	sum := a.flow.Summary(owner.ID)
	if sum == nil || len(sum.Returns) == 0 {
		return false
	}
	var retOrigins []flow.Origin
	for _, rs := range sum.Returns {
		retOrigins = append(retOrigins, rs...)
	}
	if len(retOrigins) == 0 || !a.resultBranches(owner) {
		return false
	}
	for _, out := range acc.instr.Outputs {
		deps := a.flow.DepsOf(owner, out)
		if deps == nil {
			continue
		}
		if originSliceSubset(deps, retOrigins) {
			return true
		}
	}
	return false
}

// originSliceSubset reports whether every origin in sub appears in sup.
func originSliceSubset(sub, sup []flow.Origin) bool {
	if len(sub) == 0 || len(sub) > len(sup) {
		return false
	}
	set := make(map[flow.Origin]bool, len(sup))
	for _, o := range sup {
		set[o] = true
	}
	for _, o := range sub {
		if !set[o] {
			return false
		}
	}
	return true
}

// flowReachesBranch reports whether forward value flow from v reaches
// a value used by a conditional branch. Results are cached per value.
func (a *Analyzer) flowReachesBranch(v *semantic.Value) bool {
	if v == nil {
		return false
	}
	if b, ok := a.branchCache[v]; ok {
		return b
	}
	b := false
	if a.flowQueries < a.opts.MaxFlowQueries {
		a.flowQueries++
		res := a.flow.Flow(v)
		a.flowCache[v] = res
		for _, ev := range res.Events {
			vv := a.prog.Value(ev.ValueID)
			if vv == nil {
				continue
			}
			for _, use := range a.prog.Uses(vv) {
				if use != nil && use.Op == semantic.OpBranch {
					b = true
					break
				}
			}
			if b {
				break
			}
		}
	} else {
		a.flowQueriesHit = true
	}
	a.branchCache[v] = b
	return b
}

// resultBranches reports whether any call site's result for owner may
// reach a conditional branch. Cached per function.
func (a *Analyzer) resultBranches(owner *semantic.Function) bool {
	if v, ok := a.resultBranch[owner.ID]; ok {
		return v
	}
	b := false
	for _, site := range a.flow.CallSites(owner) {
		if site == nil || site.Site == nil {
			continue
		}
		for _, out := range site.Site.Outputs {
			if a.flowReachesBranch(out) {
				b = true
				break
			}
		}
		if b {
			break
		}
	}
	a.resultBranch[owner.ID] = b
	return b
}

// pointerLikeOutput reports whether every output of the instruction is
// a pointer-like reference type (pointer, slice, map, channel,
// function). Such loads fetch references, not shared data contents.
func pointerLikeOutput(inst *semantic.Instruction) bool {
	if inst == nil || len(inst.Outputs) == 0 {
		return false
	}
	for _, out := range inst.Outputs {
		if out == nil || out.Type == nil {
			return false
		}
		switch out.Type.Kind {
		case semantic.TypePointer, semantic.TypeSlice, semantic.TypeMap, semantic.TypeChan, semantic.TypeFunc:
		default:
			return false
		}
	}
	return true
}
