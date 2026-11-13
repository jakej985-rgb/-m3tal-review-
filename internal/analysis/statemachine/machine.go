package statemachine

import (
	"fmt"
	"sort"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// This file implements the contract runtime: a single instance of a
// bound contract's state machine. The same step logic is used by the
// bounded program evaluator (eval.go) and exposed directly through
// Runtime so property-based and model-based tests can drive declared
// invariants with synthetic event sequences.

// maxHistory bounds the recorded transition history of one machine
// instance. Overflow marks the history truncated; the machine keeps
// running but evidence traces may be incomplete.
const maxHistory = 512

// HistoryEntry records one applied (or rejected) event on a machine.
type HistoryEntry struct {
	// Index is the 0-based position in the history.
	Index int
	// Event is the event name.
	Event string
	// From and To are the states before and after the step. For
	// rejected events From == To.
	From string
	To   string
	// Applied reports whether a transition fired.
	Applied bool
	// GuardUnknown reports that the enabling guard evaluated to
	// Unknown and the transition was treated as possibly enabled.
	GuardUnknown bool
	// Position is the triggering call's source position when the step
	// came from program evaluation; zero for synthetic steps.
	Position semantic.Position
	// CalleeID is the bound function ID that triggered the event,
	// when known.
	CalleeID string
	// Note carries violation or rejection detail.
	Note string
}

// EventInput is one event occurrence supplied to a machine: the event
// name plus the aligned argument values visible to expressions
// (arg[N], self). Tests construct Args directly; the evaluator derives
// them from semantic call sites.
type EventInput struct {
	Name string
	Args []Value
	// CalleeID optionally identifies the program function that
	// triggered the event (used for evidence entities).
	CalleeID string
}

// ViolationKind classifies a contract violation observed at a step.
type ViolationKind string

const (
	// ViolationIllegalTransition: the event fired in a state where no
	// transition is enabled (wrong state or all guards false).
	ViolationIllegalTransition ViolationKind = "illegal-transition"
	// ViolationInvariant: an invariant evaluated to definite false
	// after an applied transition (or in the initial state).
	ViolationInvariant ViolationKind = "invariant"
)

// Violation describes one contract violation.
type Violation struct {
	Kind ViolationKind
	// Event is the triggering event name.
	Event string
	// State is the machine state when the violation was observed.
	State string
	// Message is the human-readable description.
	Message string
	// Invariant is the violated invariant expression, for
	// ViolationInvariant.
	Invariant string
	// Transition is the applied transition index, for context.
	Transition int
}

// StepResult reports what a machine step did.
type StepResult struct {
	// Applied reports that a transition fired and effects ran.
	Applied bool
	// Transition is the index of the applied transition, or -1.
	Transition int
	// GuardUnknown reports the enabling guard was Unknown.
	GuardUnknown bool
	// Violation is non-nil when the step observed a contract
	// violation (illegal transition or invariant breach).
	Violation *Violation
}

// machine is the mutable state of one contract instance.
type machine struct {
	contract *Contract
	data     *boundContractData
	instance string

	state   string
	fields  map[string]Value
	history []HistoryEntry

	// histOverflow records that history exceeded maxHistory.
	histOverflow bool
}

// boundContractData holds bind-time resolved contract data shared by
// all machines of a contract.
type boundContractData struct {
	contract *Contract
	initial  string
	// fieldInit maps field name → initial Value.
	fieldInit map[string]Value
	// subjectArg maps event name → aligned argument index, or -1.
	subjectArg map[string]int
	// transitionsByEvent maps event name → transition indexes in
	// declaration order.
	transitionsByEvent map[string][]int
	// maxField saturates integer field arithmetic.
	maxField int64
}

func newMachine(bc *BoundContract, instance string) *machine {
	m := &machine{
		contract: bc.Contract,
		data:     bc.data,
		instance: instance,
		state:    bc.data.initial,
		fields:   make(map[string]Value, len(bc.data.fieldInit)),
	}
	for name, v := range bc.data.fieldInit {
		m.fields[name] = v
	}
	return m
}

// clone deep-copies the machine for path exploration backtracking.
func (m *machine) clone() *machine {
	out := &machine{
		contract:     m.contract,
		data:         m.data,
		instance:     m.instance,
		state:        m.state,
		fields:       make(map[string]Value, len(m.fields)),
		history:      make([]HistoryEntry, len(m.history)),
		histOverflow: m.histOverflow,
	}
	for k, v := range m.fields {
		out.fields[k] = v
	}
	copy(out.history, m.history)
	return out
}

// record appends a history entry, bounding memory.
func (m *machine) record(e HistoryEntry) {
	if len(m.history) >= maxHistory {
		m.histOverflow = true
		return
	}
	e.Index = len(m.history)
	m.history = append(m.history, e)
}

// envFor builds the expression environment for a step: contract
// fields, declared inputs, and the step's arguments.
func (m *machine) envFor(input EventInput, event string) *evalEnv {
	c := m.contract
	return &evalEnv{
		lookup: func(name string) Value {
			if v, ok := m.fields[name]; ok {
				return v
			}
			if idx, ok := c.inputIndex[name]; ok {
				return m.inputValue(c.Inputs[idx], input)
			}
			return Unknown()
		},
		arg: func(n int) Value {
			if n >= 0 && n < len(input.Args) {
				return input.Args[n]
			}
			return Unknown()
		},
		self: func() Value {
			if idx, ok := m.data.subjectArg[event]; ok && idx >= 0 && idx < len(input.Args) {
				return input.Args[idx]
			}
			return Unknown()
		},
	}
}

// inputValue resolves a declared input: an aligned call argument or a
// global reference (globals carry no modeled value → Unknown).
func (m *machine) inputValue(in InputSpec, input EventInput) Value {
	if in.Arg != nil {
		if *in.Arg >= 0 && *in.Arg < len(input.Args) {
			return input.Args[*in.Arg]
		}
		return Unknown()
	}
	// Global inputs are symbolic placeholders: the model does not
	// track global variable values, so they are always Unknown.
	return Unknown()
}

// transitionFromMatches reports whether the transition may fire from
// the given state. A nil fromStates means "any".
func transitionFromMatches(t *TransitionSpec, state string) bool {
	if t.fromStates == nil {
		return true
	}
	for _, s := range t.fromStates {
		if s == state {
			return true
		}
	}
	return false
}

// pickTransition selects the enabled transition for the machine's
// current state and event. Definite-true guards win over unknown
// guards, which win over no transition. Declaration order breaks ties
// within the same truth value.
func (m *machine) pickTransition(event string, input EventInput) (int, bool) {
	unknownIdx := -1
	for _, ti := range m.data.transitionsByEvent[event] {
		t := &m.contract.Transitions[ti]
		if !transitionFromMatches(t, m.state) {
			continue
		}
		g := m.contract.transGuards[ti]
		if g == nil {
			return ti, false
		}
		switch toTri(g.eval(m.envFor(input, event))) {
		case triTrue:
			return ti, false
		case triUnknown:
			if unknownIdx < 0 {
				unknownIdx = ti
			}
		}
	}
	if unknownIdx >= 0 {
		return unknownIdx, true
	}
	return -1, false
}

// applyEffects applies a transition's effects, saturating integer
// fields at the configured bound to keep the explored state space
// finite.
func (m *machine) applyEffects(ti int, input EventInput, event string) {
	for _, ef := range m.contract.transEffects[ti] {
		switch ef.kind {
		case "inc", "dec":
			cur := m.fields[ef.field]
			if cur.Kind != ValueInt {
				// Unknown or non-int fields stay put under inc/dec:
				// the analysis cannot prove a resulting value.
				continue
			}
			d := int64(1)
			if ef.kind == "dec" {
				d = -1
			}
			m.fields[ef.field] = Int(saturatingAdd(cur.I, d, m.data.maxField))
		case "set":
			m.fields[ef.field] = ef.expr.eval(m.envFor(input, event))
		case "reset":
			for _, f := range ef.fields {
				if init, ok := m.data.fieldInit[f]; ok {
					m.fields[f] = init
				} else {
					m.fields[f] = Int(0)
				}
			}
		}
	}
}

func saturatingAdd(a, b, bound int64) int64 {
	if bound <= 0 {
		bound = 1 << 40
	}
	r := a + b
	if r > bound {
		return bound
	}
	if r < -bound {
		return -bound
	}
	return r
}

// step applies one event to the machine. It records a history entry
// for every step, applied or rejected.
func (m *machine) step(input EventInput, pos semantic.Position) StepResult {
	res := StepResult{Transition: -1}
	from := m.state

	ti, guardUnknown := m.pickTransition(input.Name, input)
	if ti < 0 {
		res.Violation = &Violation{
			Kind:    ViolationIllegalTransition,
			Event:   input.Name,
			State:   m.state,
			Message: fmt.Sprintf("event %q is not permitted in state %q", input.Name, m.state),
		}
		m.record(HistoryEntry{
			Event: input.Name, From: from, To: from, Applied: false,
			Position: pos, Note: res.Violation.Message,
		})
		return res
	}

	t := &m.contract.Transitions[ti]
	res.Transition = ti
	res.GuardUnknown = guardUnknown
	res.Applied = true
	m.applyEffects(ti, input, input.Name)
	to := m.state
	if t.To != "" {
		to = t.To
	}
	m.state = to
	m.record(HistoryEntry{
		Event: input.Name, From: from, To: to, Applied: true,
		GuardUnknown: guardUnknown, Position: pos,
	})

	// Check invariants in the new state; the first definite violation
	// is reported (unknown invariants are treated as satisfied — the
	// analysis cannot prove a breach).
	for i, inv := range m.contract.Invariants {
		e := m.contract.invExprs[i]
		if e == nil {
			continue
		}
		if toTri(e.eval(m.envFor(input, input.Name))) == triFalse {
			msg := fmt.Sprintf("invariant %q is violated in state %q after event %q", inv.Expr, m.state, input.Name)
			if inv.Message != "" {
				msg = inv.Message
			}
			res.Violation = &Violation{
				Kind:       ViolationInvariant,
				Event:      input.Name,
				State:      m.state,
				Message:    msg,
				Invariant:  inv.Expr,
				Transition: ti,
			}
			return res
		}
	}
	return res
}

// ---------------------------------------------------------------------
// Public Runtime API (model/property-based testing route)
// ---------------------------------------------------------------------

// Runtime drives one instance of a bound contract's state machine. It
// is the exported, deterministic route for property-based and
// model-based tests: feed EventInput sequences and observe StepResult
// violations without any program analysis.
type Runtime struct {
	m *machine
}

// NewRuntime returns a Runtime for the contract instance. The
// instance name is arbitrary ("" selects the shared "self" instance);
// it only labels reports.
func (bc *BoundContract) NewRuntime(instance string) *Runtime {
	if instance == "" {
		instance = "self"
	}
	return &Runtime{m: newMachine(bc, instance)}
}

// Step applies one event. Each Runtime is single-goroutine; create
// separate Runtimes for concurrent use.
func (r *Runtime) Step(ev EventInput) StepResult {
	return r.m.step(ev, semantic.Position{})
}

// State returns the current state name.
func (r *Runtime) State() string { return r.m.state }

// Field returns the current value of a contract field (Unknown when
// undeclared).
func (r *Runtime) Field(name string) Value { return r.m.fields[name] }

// Fields returns the sorted field names.
func (r *Runtime) Fields() []string {
	out := make([]string, 0, len(r.m.fields))
	for k := range r.m.fields {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// History returns a copy of the recorded transition history.
func (r *Runtime) History() []HistoryEntry {
	return append([]HistoryEntry(nil), r.m.history...)
}

// Instance returns the runtime's instance label.
func (r *Runtime) Instance() string { return r.m.instance }

// InvariantCheck evaluates all invariants in the current state and
// returns the first violated invariant expression ("" when all hold
// or evaluate to unknown).
func (r *Runtime) InvariantCheck() string {
	input := EventInput{}
	for i, inv := range r.m.contract.Invariants {
		e := r.m.contract.invExprs[i]
		if e == nil {
			continue
		}
		if toTri(e.eval(r.m.envFor(input, ""))) == triFalse {
			return inv.Expr
		}
	}
	return ""
}
