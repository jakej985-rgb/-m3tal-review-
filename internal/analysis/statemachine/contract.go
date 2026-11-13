package statemachine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"gopkg.in/yaml.v3"
)

// SchemaVersion is the only contract schema version this package
// understands. The version is carried in every contract document
// (`schema_version: statemachine/1`) so future revisions can coexist.
const SchemaVersion = "statemachine/1"

// Contract is a versioned, declarative state-machine contract. It is
// language-neutral: contracts bind to program entities structurally
// through the semantic program model (function IDs, signatures,
// receiver types, call edges), never through frontend-specific syntax.
//
// A Contract is parsed from YAML (JSON is accepted as a YAML subset)
// and validated by Check; binding to a program happens in Bind.
// Contracts must not be copied after use: parsed expressions and
// validation results are cached in unexported fields.
type Contract struct {
	SchemaVersion string `yaml:"schema_version"`
	// ID is a stable contract identifier used in diagnostics, finding
	// metadata, and sequence reports. Defaults to "contract".
	ID string `yaml:"id"`
	// Name and Description are human-readable documentation.
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	// Resource optionally declares the subject type the contract
	// governs (e.g. "example.com/x.Token" or "*example.com/x.Token").
	// When present it is bound structurally against the program's
	// declared types; an unbound resource is reported, not guessed.
	Resource *ResourceSpec `yaml:"resource"`

	// States declares the finite state set. Exactly one state must be
	// marked initial.
	States []StateSpec `yaml:"states"`
	// Events declares named events. An event may bind to a program
	// function; unbound events never fire during program evaluation
	// but remain usable with Runtime for model-based tests.
	Events []EventSpec `yaml:"events"`
	// Transitions declare the legal moves. Transitions are evaluated
	// in declaration order for a given (state, event) pair.
	Transitions []TransitionSpec `yaml:"transitions"`
	// Invariants are predicates that must hold after every applied
	// transition (and in the initial state). A definite false
	// evaluation is a violation finding.
	Invariants []InvariantSpec `yaml:"invariants"`

	// Fields declares contract-tracked data (counters, timestamps,
	// flags). Fields may also be introduced implicitly by transition
	// effects; undeclared reads in expressions are rejected.
	Fields []FieldSpec `yaml:"fields"`
	// Inputs declares named per-trigger values (typically call
	// arguments such as a clock reading) usable in expressions.
	Inputs []InputSpec `yaml:"inputs"`

	// Entry optionally lists function bindings that seed the bounded
	// path exploration. When empty, every modeled function with a
	// body is a potential entry point.
	Entry []FunctionSpec `yaml:"entry"`

	// OnUnhandled controls what happens when a bound event fires with
	// no enabled transition: "report" (default) emits a finding;
	// "ignore" treats it as outside the contract's scope.
	OnUnhandled string `yaml:"on_unhandled"`

	// prepared caches parse/validation results.
	prepared bool
	diags    []analysis.Diagnostic

	stateIndex   map[string]int
	eventIndex   map[string]int
	fieldIndex   map[string]int
	inputIndex   map[string]int
	transGuards  []expr
	transEffects [][]effect
	invExprs     []expr
	invRaw       []string
	// invalidT marks transition indexes that must not fire: unknown
	// event or unparsable guard.
	invalidT map[int]bool
}

// ResourceSpec binds a contract to a subject type.
type ResourceSpec struct {
	// Type is "[pkg/path][*].Name" — e.g. "example.com/x.Token" or
	// "*example.com/x.Token". The package path is matched against
	// semantic package paths and the name against declared type names.
	Type string `yaml:"type"`
}

// StateSpec declares one state.
type StateSpec struct {
	Name        string `yaml:"name"`
	Initial     bool   `yaml:"initial"`
	Description string `yaml:"description"`
}

// FunctionSpec structurally binds a contract element to program
// functions. At least one of ID or Name must be set. Matching is
// structural: ID is exact, Name is filtered by Package path and
// Receiver type when given. Zero matches is "unbound"; multiple
// matches is "ambiguous" — both are reported, never guessed.
type FunctionSpec struct {
	// ID is an exact semantic function ID (e.g.
	// "example.com/x.(*Token).Consume").
	ID string `yaml:"id"`
	// Name is the function's short name (e.g. "Consume").
	Name string `yaml:"name"`
	// Package optionally restricts matches to a package import path.
	Package string `yaml:"package"`
	// Receiver optionally restricts matches to methods whose receiver
	// base type is "[pkg/path.]Name" (pointers are unwrapped).
	Receiver string `yaml:"receiver"`
}

// EventSpec declares a named event and its optional function binding.
type EventSpec struct {
	Name        string        `yaml:"name"`
	Description string        `yaml:"description"`
	Function    *FunctionSpec `yaml:"function"`
	// SubjectArg is the index (in the aligned argument list, where
	// index 0 is the receiver for methods) of the call argument that
	// identifies the resource instance the event applies to. -1 means
	// the event applies to the contract's single shared instance.
	// Default 0.
	SubjectArg *int `yaml:"subject_arg"`
}

// TransitionSpec declares one legal move.
type TransitionSpec struct {
	// Event names the triggering event (must be declared in Events).
	Event string `yaml:"event"`
	// From lists the source states, or "any" for all states. Required.
	From interface{} `yaml:"from"`
	// To is the target state. Empty means "stay in the current state".
	To string `yaml:"to"`
	// Guard is an optional expression that must not evaluate to false
	// for the transition to be enabled. Unknown guards are treated as
	// possibly enabled (may-analysis) and recorded as assumptions.
	Guard string `yaml:"guard"`
	// Effects is a list of state updates applied when the transition
	// fires: `inc: field`, `dec: field`, `set: field = expr`,
	// `reset: field` or `reset: [f1, f2]`.
	Effects []interface{} `yaml:"effects"`
	// Description documents the transition.
	Description string `yaml:"description"`

	fromStates []string // nil means "any"
}

// InvariantSpec declares a predicate checked after every transition.
type InvariantSpec struct {
	Expr    string `yaml:"expr"`
	Message string `yaml:"message"`
}

// FieldSpec declares a tracked field.
type FieldSpec struct {
	Name        string      `yaml:"name"`
	Kind        string      `yaml:"kind"` // "int" (default) or "bool"
	Initial     interface{} `yaml:"initial"`
	Description string      `yaml:"description"`
}

// InputSpec declares a named per-trigger input usable in expressions.
// Exactly one of Arg or Global must be set.
type InputSpec struct {
	Name   string `yaml:"name"`
	Arg    *int   `yaml:"arg"`
	Global string `yaml:"global"`
}

// effect is a parsed transition effect.
type effect struct {
	kind   string // "inc", "dec", "set", "reset"
	field  string
	expr   expr     // for "set"
	fields []string // for "reset"
}

// ---------------------------------------------------------------------
// Parsing and validation
// ---------------------------------------------------------------------

// ParseContract parses a contract document. YAML is the canonical
// format; JSON documents parse as a YAML subset. A non-nil error is
// returned only for unreadable input or a wrong/missing schema
// version; semantic problems (unknown states, bad expressions,
// duplicate names) are reported through Check.
func ParseContract(data []byte) (*Contract, error) {
	var raw struct {
		Contract `yaml:",inline"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("statemachine contract: %w", err)
	}
	c := raw.Contract
	if c.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("statemachine contract: unsupported schema_version %q (want %q)", c.SchemaVersion, SchemaVersion)
	}
	if c.ID == "" {
		c.ID = "contract"
	}
	return &c, nil
}

// Check validates the contract and returns all problems found, sorted
// deterministically. It also parses and caches guard, invariant, and
// effect expressions; expressions that fail to parse are reported and
// treated as unsupported during evaluation. Check is idempotent.
func (c *Contract) Check() []analysis.Diagnostic {
	if c.prepared {
		return c.diags
	}
	c.prepared = true
	var diags []analysis.Diagnostic
	add := func(sev analysis.DiagnosticSeverity, cat analysis.DiagnosticCategory, msg string) {
		diags = append(diags, analysis.Diagnostic{Severity: sev, Category: cat, Message: msg})
	}

	// States.
	c.stateIndex = make(map[string]int)
	initials := 0
	for i, s := range c.States {
		if s.Name == "" {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("states[%d]: name is required", i))
			continue
		}
		if _, dup := c.stateIndex[s.Name]; dup {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("duplicate state %q", s.Name))
			continue
		}
		c.stateIndex[s.Name] = i
		if s.Initial {
			initials++
		}
	}
	if len(c.States) == 0 {
		add(analysis.DiagSeverityError, analysis.DiagParseError, "contract declares no states")
	} else if initials != 1 {
		add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("contract must declare exactly one initial state, found %d", initials))
	}

	// Events.
	c.eventIndex = make(map[string]int)
	for i, e := range c.Events {
		if e.Name == "" {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("events[%d]: name is required", i))
			continue
		}
		if _, dup := c.eventIndex[e.Name]; dup {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("duplicate event %q", e.Name))
			continue
		}
		c.eventIndex[e.Name] = i
	}

	// Fields and inputs: names must be valid identifiers and unique
	// across both namespaces (expressions resolve them in one
	// environment).
	c.fieldIndex = make(map[string]int)
	declared := make(map[string]bool)
	for i, f := range c.Fields {
		if !validIdent(f.Name) {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("fields[%d]: invalid name %q", i, f.Name))
			continue
		}
		if _, dup := c.fieldIndex[f.Name]; dup {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("duplicate field %q", f.Name))
			continue
		}
		c.fieldIndex[f.Name] = i
		declared[f.Name] = true
	}
	c.inputIndex = make(map[string]int)
	for i, in := range c.Inputs {
		if !validIdent(in.Name) {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("inputs[%d]: invalid name %q", i, in.Name))
			continue
		}
		if _, dup := c.inputIndex[in.Name]; dup {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("duplicate input %q", in.Name))
			continue
		}
		if declared[in.Name] {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("input %q collides with a field name", in.Name))
			continue
		}
		if (in.Arg == nil) == (in.Global == "") {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("inputs[%d] %q: exactly one of arg or global is required", i, in.Name))
			continue
		}
		c.inputIndex[in.Name] = i
		declared[in.Name] = true
	}

	// Transitions, pass 1: parse effects and pre-declare their write
	// targets so guards and invariants may read fields that are only
	// ever written (not read) by effects.
	c.transEffects = make([][]effect, len(c.Transitions))
	for i := range c.Transitions {
		t := &c.Transitions[i]
		where := fmt.Sprintf("transitions[%d]", i)
		effects, err := parseEffects(t.Effects)
		if err != nil {
			add(analysis.DiagSeverityError, analysis.DiagUnsupported, where+": "+err.Error())
			continue
		}
		c.transEffects[i] = effects
		for _, ef := range effects {
			targets := ef.fields
			if ef.kind == "inc" || ef.kind == "dec" || ef.kind == "set" {
				targets = []string{ef.field}
			}
			for _, f := range targets {
				if _, ok := c.fieldIndex[f]; !ok {
					c.fieldIndex[f] = len(c.Fields)
					c.Fields = append(c.Fields, FieldSpec{Name: f, Kind: "int"})
					declared[f] = true
				}
			}
		}
	}

	// Transitions, pass 2: validate structure and guards.
	c.transGuards = make([]expr, len(c.Transitions))
	c.invalidT = make(map[int]bool)
	for i := range c.Transitions {
		t := &c.Transitions[i]
		where := fmt.Sprintf("transitions[%d]", i)
		if t.Event == "" {
			add(analysis.DiagSeverityError, analysis.DiagParseError, where+": event is required")
			c.invalidT[i] = true
		} else if _, ok := c.eventIndex[t.Event]; !ok {
			add(analysis.DiagSeverityError, analysis.DiagParseError, where+": unknown event "+quote(t.Event))
			c.invalidT[i] = true
		}
		from, ok := parseFrom(t.From)
		if !ok {
			add(analysis.DiagSeverityError, analysis.DiagParseError, where+": from must be a state name, \"any\", or a list of state names")
		} else {
			t.fromStates = from
			for _, s := range from {
				if _, ok := c.stateIndex[s]; !ok {
					add(analysis.DiagSeverityError, analysis.DiagParseError, where+": unknown from-state "+quote(s))
				}
			}
		}
		if t.To != "" {
			if _, ok := c.stateIndex[t.To]; !ok {
				add(analysis.DiagSeverityError, analysis.DiagParseError, where+": unknown to-state "+quote(t.To))
			}
		}
		if strings.TrimSpace(t.Guard) != "" {
			e, err := parseExpr(t.Guard)
			if err != nil {
				add(analysis.DiagSeverityError, analysis.DiagUnsupported, where+": guard expression: "+err.Error())
				c.invalidT[i] = true
			} else {
				c.transGuards[i] = e
				for _, name := range exprRefs(e) {
					if !declared[name] {
						add(analysis.DiagSeverityError, analysis.DiagParseError, where+": guard references undeclared name "+quote(name))
					}
				}
			}
		}
		for _, ef := range c.transEffects[i] {
			if ef.kind == "set" {
				for _, name := range exprRefs(ef.expr) {
					if !declared[name] {
						add(analysis.DiagSeverityError, analysis.DiagParseError, where+": effect expression references undeclared name "+quote(name))
					}
				}
			}
		}
	}

	// Invariants.
	c.invExprs = make([]expr, len(c.Invariants))
	c.invRaw = make([]string, len(c.Invariants))
	for i, inv := range c.Invariants {
		where := fmt.Sprintf("invariants[%d]", i)
		if strings.TrimSpace(inv.Expr) == "" {
			add(analysis.DiagSeverityError, analysis.DiagParseError, where+": expr is required")
			continue
		}
		e, err := parseExpr(inv.Expr)
		if err != nil {
			add(analysis.DiagSeverityError, analysis.DiagUnsupported, where+": "+err.Error())
			continue
		}
		c.invExprs[i] = e
		c.invRaw[i] = inv.Expr
		for _, name := range exprRefs(e) {
			if !declared[name] {
				add(analysis.DiagSeverityError, analysis.DiagParseError, where+": references undeclared name "+quote(name))
			}
		}
	}

	sort.SliceStable(diags, func(i, j int) bool {
		if diags[i].Message != diags[j].Message {
			return diags[i].Message < diags[j].Message
		}
		return diags[i].Category < diags[j].Category
	})
	c.diags = diags
	return diags
}

// Diagnostics returns the contract's validation diagnostics.
func (c *Contract) Diagnostics() []analysis.Diagnostic { return c.Check() }

func quote(s string) string { return fmt.Sprintf("%q", s) }

func validIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// parseFrom normalizes a transition's from field: a string ("any" or a
// state name) or a list of state names. It returns nil,nil for "any".
func parseFrom(v interface{}) ([]string, bool) {
	switch t := v.(type) {
	case string:
		if t == "any" || t == "*" {
			return nil, true
		}
		return []string{t}, true
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	case nil:
		return nil, false
	}
	return nil, false
}

// parseEffects parses the effects list. Each element is a single-key
// map: {inc: field}, {dec: field}, {set: "field = expr"}, or
// {reset: field|[fields]}.
func parseEffects(raw []interface{}) ([]effect, error) {
	var out []effect
	for i, item := range raw {
		m, ok := item.(map[string]interface{})
		if !ok || len(m) != 1 {
			return nil, fmt.Errorf("effects[%d]: each effect must be a single-key mapping (inc/dec/set/reset)", i)
		}
		for kind, val := range m {
			switch kind {
			case "inc", "dec":
				f, ok := val.(string)
				if !ok || !validIdent(f) {
					return nil, fmt.Errorf("effects[%d]: %s requires a field name", i, kind)
				}
				out = append(out, effect{kind: kind, field: f})
			case "set":
				s, ok := val.(string)
				if !ok {
					return nil, fmt.Errorf("effects[%d]: set requires \"field = expr\"", i)
				}
				lhs, rhs, found := strings.Cut(s, "=")
				if !found {
					return nil, fmt.Errorf("effects[%d]: set requires \"field = expr\"", i)
				}
				field := strings.TrimSpace(lhs)
				if !validIdent(field) {
					return nil, fmt.Errorf("effects[%d]: invalid set target %q", i, field)
				}
				e, err := parseExpr(strings.TrimSpace(rhs))
				if err != nil {
					return nil, fmt.Errorf("effects[%d]: set expression: %w", i, err)
				}
				out = append(out, effect{kind: "set", field: field, expr: e})
			case "reset":
				switch v := val.(type) {
				case string:
					if !validIdent(v) {
						return nil, fmt.Errorf("effects[%d]: invalid reset target %q", i, v)
					}
					out = append(out, effect{kind: "reset", fields: []string{v}})
				case []interface{}:
					var fields []string
					for _, e := range v {
						s, ok := e.(string)
						if !ok || !validIdent(s) {
							return nil, fmt.Errorf("effects[%d]: invalid reset target", i)
						}
						fields = append(fields, s)
					}
					out = append(out, effect{kind: "reset", fields: fields})
				default:
					return nil, fmt.Errorf("effects[%d]: reset requires a field name or list", i)
				}
			default:
				return nil, fmt.Errorf("effects[%d]: unknown effect %q (want inc/dec/set/reset)", i, kind)
			}
		}
	}
	return out, nil
}
