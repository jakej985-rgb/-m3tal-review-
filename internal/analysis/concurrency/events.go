package concurrency

import (
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// fevKind classifies a flattened function event.
type fevKind int

const (
	// fevAcquire is a lock acquisition (Lock, RLock, TryLock, ...).
	fevAcquire fevKind = iota
	// fevRelease is a lock release (Unlock, RUnlock).
	fevRelease
	// fevRead is a shared-state read (load, index, slice, type assert,
	// atomic load, atomic read-modify-write).
	fevRead
	// fevWrite is a shared-state write (store, map update, atomic
	// store, atomic read-modify-write, delete, copy destination).
	fevWrite
	// fevNote marks an event relevant to diagnostics and trace
	// completeness but carrying no lock/access semantics (channel
	// ops, unsupported sync primitives, opaque calls).
	fevNote
)

// lockKind distinguishes mutex write locks from RWMutex read locks.
type lockKind int

const (
	lockWrite lockKind = iota
	lockRead
)

// fev is one flattened, function-relative event: a lock operation, a
// shared-state access, or an informational note. Events are produced
// per function by flatEvents with keys scoped to that function; when a
// function is inlined into a caller, keys are translated and path is
// prefixed so section-instance identity stays unique per call path.
// Deferred effects are appended at the end of the function's event
// list, so list position alone encodes effect order.
type fev struct {
	kind  fevKind
	owner *semantic.Function
	instr *semantic.Instruction
	path  string // call-path prefix for section-instance identity
	lock  lockKind
	try   bool // conditional acquisition (TryLock/TryRLock)
	keys  []stateKey
	note  string // fevNote payload
}

// syncClass classifies a call target with respect to synchronization.
type syncClass int

const (
	syncNone syncClass = iota
	// syncMutexOp is a recognized sync.Mutex / sync.RWMutex method.
	syncMutexOp
	// syncAtomicOp is a sync/atomic function.
	syncAtomicOp
	// syncUnsupported is a recognized synchronization primitive the
	// analyzer does not model as mutual exclusion (Once, WaitGroup,
	// Map, Pool, Cond, x/sync semaphore, ...).
	syncUnsupported
)

// mutexMethod describes one recognized mutex method.
type mutexMethod struct {
	acquire bool
	read    bool // RWMutex read lock side (RLock/RUnlock)
	try     bool
}

// mutexMethods maps sync.Mutex / sync.RWMutex method names.
var mutexMethods = map[string]mutexMethod{
	"Lock":     {acquire: true},
	"Unlock":   {},
	"TryLock":  {acquire: true, try: true},
	"RLock":    {acquire: true, read: true},
	"RUnlock":  {read: true},
	"TryRLock": {acquire: true, read: true, try: true},
}

// classifySync reports how callee participates in synchronization.
// It is the Go-flavored edge of the otherwise language-neutral
// analysis: recognition is by package path + receiver type + method
// name, which is how the semantic model renders Go declarations.
func (a *Analyzer) classifySync(callee *semantic.Function) (syncClass, mutexMethod) {
	if callee == nil || callee.Package == nil {
		return syncNone, mutexMethod{}
	}
	path := callee.Package.Path
	if path == "sync/atomic" {
		return syncAtomicOp, mutexMethod{}
	}
	if path == "sync" {
		if callee.Receiver != nil && isMutexType(callee.Receiver) {
			if m, ok := mutexMethods[callee.Name]; ok {
				return syncMutexOp, m
			}
		}
		// Package initializers and synthetic init helpers are
		// ordinary calls, not synchronization primitives. Other
		// synthetic sync declarations (e.g. (*sync.Once).Do) are
		// unsupported primitives and stay visible.
		if callee.Kind == semantic.FuncInit || (callee.Synthetic && callee.Name == "init") {
			return syncNone, mutexMethod{}
		}
		return syncUnsupported, mutexMethod{}
	}
	if path == "golang.org/x/sync/semaphore" {
		return syncUnsupported, mutexMethod{}
	}
	return syncNone, mutexMethod{}
}

// isMutexType reports whether t is sync.Mutex or sync.RWMutex (or a
// pointer to one).
func isMutexType(t *semantic.Type) bool {
	if t == nil {
		return false
	}
	if t.Kind == semantic.TypePointer {
		t = t.Elem
	}
	if t == nil {
		return false
	}
	return t.Package == "sync" && (t.Name == "Mutex" || t.Name == "RWMutex")
}

// atomicAccessKind classifies a sync/atomic function by name:
// Load* reads, Store* writes, everything else (Add*, Swap*,
// CompareAndSwap*) reads and writes.
func atomicAccessKind(name string) (read, write bool) {
	switch {
	case strings.HasPrefix(name, "Load"):
		return true, false
	case strings.HasPrefix(name, "Store"):
		return false, true
	default:
		return true, true
	}
}

// ---------------------------------------------------------------------
// Flattening
// ---------------------------------------------------------------------

// flatEvents returns the flattened event list for fn: its own
// straight-line events followed by the events of deferred calls
// (which run at function exit). Callee events are inlined at their
// call sites with keys translated into fn's scope. The result is
// memoized per function; paths inside are relative to fn.
func (a *Analyzer) flatEvents(fn *semantic.Function) []fev {
	if fn == nil {
		return nil
	}
	if evs, ok := a.eventCache[fn.ID]; ok {
		return evs
	}
	if a.eventInProgress[fn.ID] {
		a.note("recursive call cycle through " + fn.ID + "; inlining stopped at the cycle")
		return nil
	}
	a.eventInProgress[fn.ID] = true
	var out []fev
	// Straight-line pass: everything except deferred calls.
	for _, b := range fn.Blocks {
		for _, ins := range b.Instructions {
			if len(out) >= a.opts.MaxEventsPerFunc {
				a.truncatedEvents(fn)
				break
			}
			if call := a.prog.CallAt(ins); call != nil {
				if call.Kind == semantic.CallDefer {
					continue
				}
				out = a.callEvents(fn, ins, call, out)
				continue
			}
			out = a.instrEvents(fn, ins, out)
		}
	}
	// Deferred pass: deferred calls run at function exit, so their
	// effects append after all straight-line events.
	for _, b := range fn.Blocks {
		for _, ins := range b.Instructions {
			call := a.prog.CallAt(ins)
			if call == nil || call.Kind != semantic.CallDefer {
				continue
			}
			if len(out) >= a.opts.MaxEventsPerFunc {
				a.truncatedEvents(fn)
				break
			}
			out = a.callEvents(fn, ins, call, out)
		}
	}
	delete(a.eventInProgress, fn.ID)
	a.eventCache[fn.ID] = out
	return out
}

func (a *Analyzer) truncatedEvents(fn *semantic.Function) {
	a.truncated = true
	a.note("event list for " + fn.ID + " exceeded MaxEventsPerFunc; later accesses were dropped")
}

// callEvents handles one call-site instruction, appending the events
// it contributes to out. CallDefer sites are only reached from the
// deferred pass, so their events land at the end of the function's
// list automatically.
func (a *Analyzer) callEvents(fn *semantic.Function, ins *semantic.Instruction, call *semantic.Call, out []fev) []fev {
	callees := a.calleesOf(ins, call)
	if len(callees) == 0 {
		return a.unresolvedCallEvents(fn, ins, call, out)
	}

	// Group recognized mutex operations by operation class so a
	// dynamic may-set of identical lock calls merges into one event
	// carrying the union of mutex keys.
	type mgroup struct {
		mm   mutexMethod
		keys []stateKey
	}
	groups := make(map[string]*mgroup)
	var gorder []string

	for _, callee := range callees {
		if callee == nil {
			continue
		}
		cls, mm := a.classifySync(callee)
		switch cls {
		case syncMutexOp:
			gk := mutexGroupKey(mm)
			g := groups[gk]
			if g == nil {
				g = &mgroup{mm: mm}
				groups[gk] = g
				gorder = append(gorder, gk)
			}
			g.keys = mergeKeys(g.keys, a.mutexKeys(fn, ins, call, callee))
		case syncAtomicOp:
			out = append(out, a.atomicEvents(fn, ins, call, callee)...)
		case syncUnsupported:
			out = append(out, fev{kind: fevNote, owner: fn, instr: ins, note: "unsupported sync primitive: " + callee.ID})
			a.noteUnsupported(callee)
		default:
			out = a.inlineCallee(fn, ins, call, callee, out)
		}
	}
	sort.Strings(gorder)
	for _, gk := range gorder {
		g := groups[gk]
		kind := fevRelease
		if g.mm.acquire {
			kind = fevAcquire
		}
		lk := lockWrite
		if g.mm.read {
			lk = lockRead
		}
		out = append(out, fev{
			kind:  kind,
			owner: fn,
			instr: ins,
			lock:  lk,
			try:   g.mm.try,
			keys:  g.keys,
		})
		if len(g.keys) == 0 {
			out = append(out, fev{kind: fevNote, owner: fn, instr: ins, note: "lock operation on an unidentifiable mutex; treated as no proven mutual exclusion"})
		}
	}
	return out
}

func mutexGroupKey(mm mutexMethod) string {
	return itoa(boolInt(mm.acquire)) + "/" + itoa(boolInt(mm.read)) + "/" + itoa(boolInt(mm.try))
}

// unresolvedCallEvents handles call sites with no modeled callees:
// builtins with shared-state effects, dynamic targets, and unmodeled
// calls.
func (a *Analyzer) unresolvedCallEvents(fn *semantic.Function, ins *semantic.Instruction, call *semantic.Call, out []fev) []fev {
	if call.Dynamic {
		out = append(out, fev{kind: fevNote, owner: fn, instr: ins, note: "unresolved dynamic call target"})
		a.dynamicCalls++
		return out
	}
	if name := builtinName(call); name != "" {
		return a.builtinEvents(fn, ins, name, out)
	}
	out = append(out, fev{kind: fevNote, owner: fn, instr: ins, note: "unmodeled call target"})
	a.opaqueCalls++
	return out
}

// inlineCallee splices a callee's flattened events into the caller's
// stream at the call site, translating state keys into the caller's
// scope and prefixing section-instance paths.
func (a *Analyzer) inlineCallee(fn *semantic.Function, ins *semantic.Instruction, call *semantic.Call, callee *semantic.Function, out []fev) []fev {
	if call.Kind == semantic.CallGo {
		// The callee runs on a new goroutine: it is analyzed as its
		// own trace root, never inlined into the spawner's stream.
		return out
	}
	if len(callee.Blocks) == 0 {
		// External or bodiless callee: its shared-state effects are
		// opaque. Counted for diagnostics; not modeled.
		a.opaqueCalls++
		return out
	}
	child := a.flatEvents(callee)
	if len(child) == 0 {
		return out
	}
	actuals := a.flow.ActualsFor(ins, call, callee)
	prefix := fn.ID + "@" + instrID(ins) + "/"
	for _, ev := range child {
		cev := ev
		cev.path = prefix + ev.path
		cev.keys = a.translateKeys(ev.keys, fn, callee, actuals)
		out = append(out, cev)
	}
	return out
}

// callArgs returns the call's argument values in operand order,
// excluding the callee value for ordinary calls. External callees
// (e.g. sync.Mutex methods) carry no modeled parameter list, so the
// flow analyzer's ActualsFor cannot be used for them; the operand
// layout rules mirror flow.actualsFor.
func (a *Analyzer) callArgs(ins *semantic.Instruction, call *semantic.Call, callee *semantic.Function) []*semantic.Value {
	ops := ins.Operands
	if call.Kind == semantic.CallDefer && len(ops) > 1 {
		last := ops[len(ops)-1]
		if last != nil && last.Name == "deferStack" {
			ops = ops[:len(ops)-1]
		}
	}
	if len(ops) == 0 {
		return nil
	}
	if call.Dynamic && callee != nil && callee.Receiver != nil {
		// Interface invoke: operand 0 is the receiver actual.
		return ops
	}
	return ops[1:]
}

// mutexKeys computes the state keys identifying the mutex operand of
// a lock/unlock call: the receiver actual's places (or origin
// fallback). External mutex methods have no modeled parameters, so
// the receiver is taken from the call operands directly.
func (a *Analyzer) mutexKeys(fn *semantic.Function, ins *semantic.Instruction, call *semantic.Call, callee *semantic.Function) []stateKey {
	args := a.callArgs(ins, call, callee)
	if len(args) == 0 || args[0] == nil {
		return nil
	}
	return a.valueKeys(fn, args[0])
}

// atomicEvents emits read/write access events for a sync/atomic call.
// The accessed state is the pointer argument (first argument).
func (a *Analyzer) atomicEvents(fn *semantic.Function, ins *semantic.Instruction, call *semantic.Call, callee *semantic.Function) []fev {
	args := a.callArgs(ins, call, callee)
	if len(args) == 0 || args[0] == nil {
		return nil
	}
	keys := a.valueKeys(fn, args[0])
	if len(keys) == 0 {
		return nil
	}
	read, write := atomicAccessKind(callee.Name)
	var out []fev
	if read {
		out = append(out, fev{kind: fevRead, owner: fn, instr: ins, keys: keys})
	}
	if write {
		out = append(out, fev{kind: fevWrite, owner: fn, instr: ins, keys: keys})
	}
	a.atomicOps++
	return out
}

// builtinEvents handles calls to language builtins. Only builtins with
// shared-state effects produce events: delete writes its map operand,
// copy writes its destination, close synchronizes on a channel
// (noted, not modeled as a lock).
func (a *Analyzer) builtinEvents(fn *semantic.Function, ins *semantic.Instruction, name string, out []fev) []fev {
	switch name {
	case "close":
		out = append(out, fev{kind: fevNote, owner: fn, instr: ins, note: "channel close (synchronization not modeled as mutual exclusion)"})
		a.channelOps++
	case "delete", "copy":
		// For builtin calls the modeled operands are the call
		// arguments directly (no callee slot). delete(m, k) writes m;
		// copy(dst, src, ...) writes dst and reads src.
		argStart := 0
		if len(ins.Operands) > 0 && ins.Operands[0] != nil && ins.Operands[0].Kind == semantic.ValueBuiltin {
			argStart = 1
		}
		if name == "delete" {
			if len(ins.Operands) > argStart {
				if keys := a.valueKeys(fn, ins.Operands[argStart]); len(keys) > 0 {
					out = append(out, fev{kind: fevWrite, owner: fn, instr: ins, keys: keys})
				}
			}
		} else {
			if len(ins.Operands) > argStart {
				if keys := a.valueKeys(fn, ins.Operands[argStart]); len(keys) > 0 {
					out = append(out, fev{kind: fevWrite, owner: fn, instr: ins, keys: keys})
				}
			}
			if len(ins.Operands) > argStart+1 {
				if keys := a.valueKeys(fn, ins.Operands[argStart+1]); len(keys) > 0 {
					out = append(out, fev{kind: fevRead, owner: fn, instr: ins, keys: keys})
				}
			}
		}
	}
	return out
}

// instrEvents converts a non-call instruction into access events.
func (a *Analyzer) instrEvents(fn *semantic.Function, ins *semantic.Instruction, out []fev) []fev {
	switch ins.Op {
	case semantic.OpStore:
		if len(ins.Operands) >= 1 {
			if keys := a.valueKeys(fn, ins.Operands[0]); len(keys) > 0 {
				out = append(out, fev{kind: fevWrite, owner: fn, instr: ins, keys: keys})
			}
		}
	case semantic.OpSend, semantic.OpRecv:
		out = append(out, fev{kind: fevNote, owner: fn, instr: ins, note: "channel operation (happens-before not modeled as mutual exclusion)"})
		a.channelOps++
	case semantic.OpOther:
		if ins.Detail == "MapUpdate" && len(ins.Operands) >= 1 {
			if keys := a.valueKeys(fn, ins.Operands[0]); len(keys) > 0 {
				out = append(out, fev{kind: fevWrite, owner: fn, instr: ins, keys: keys})
			}
		}
	default:
		if isReadOp(ins.Op) && len(ins.Operands) >= 1 {
			if keys := a.valueKeys(fn, ins.Operands[0]); len(keys) > 0 {
				out = append(out, fev{kind: fevRead, owner: fn, instr: ins, keys: keys})
			}
		}
	}
	return out
}

// isReadOp mirrors the flow analyzer's read-op set minus OpRecv:
// channel receives synchronize rather than read shared program state.
func isReadOp(op semantic.Op) bool {
	switch op {
	case semantic.OpLoad, semantic.OpIndex, semantic.OpSlice, semantic.OpTypeAssert:
		return true
	}
	return false
}

// calleesOf returns the effective callee may-set for a call site,
// including the direct function-value fallback used by the flow
// analyzer.
func (a *Analyzer) calleesOf(ins *semantic.Instruction, call *semantic.Call) []*semantic.Function {
	callees := call.Callees
	if len(callees) == 0 && len(ins.Operands) > 0 {
		if fv := ins.Operands[0]; fv != nil && fv.Kind == semantic.ValueFunction && fv.Func != nil {
			callees = []*semantic.Function{fv.Func}
		}
	}
	return callees
}

// builtinName extracts the builtin name from a call's target text
// ("builtin: delete").
func builtinName(call *semantic.Call) string {
	if strings.HasPrefix(call.Target, "builtin: ") {
		return strings.TrimPrefix(call.Target, "builtin: ")
	}
	return ""
}

func instrID(ins *semantic.Instruction) string {
	return itoa(ins.ID)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// mergeKeys unions two key lists, deduplicating by canonical string.
func mergeKeys(a, b []stateKey) []stateKey {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]stateKey, 0, len(a)+len(b))
	for _, k := range append(append([]stateKey{}, a...), b...) {
		s := k.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
