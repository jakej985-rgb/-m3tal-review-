package statemachine

import (
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// ValueKind classifies a contract-evaluation value. The domain is
// deliberately small: contract guards and effects reason about
// counters, timestamps, flags, and state names — not arbitrary program
// data.
type ValueKind int

const (
	// ValueUnknown is the "may be anything" value produced whenever the
	// underlying program fact cannot be determined (non-constant call
	// arguments, unanalyzed functions, unsupported expressions).
	// Three-valued logic applies: comparisons involving Unknown yield
	// Unknown, and Unknown guards/invariants are treated as
	// *possibly* satisfied (may-analysis).
	ValueUnknown ValueKind = iota
	// ValueInt is a signed 64-bit integer (counters, timestamps,
	// durations, attempt indexes).
	ValueInt
	// ValueBool is a boolean (flags, lock state).
	ValueBool
	// ValueString is a short string (state names, tags).
	ValueString
)

// Value is a contract-domain value. The zero value is Unknown.
type Value struct {
	Kind ValueKind
	I    int64
	B    bool
	S    string
}

// Unknown returns the unknown value.
func Unknown() Value { return Value{Kind: ValueUnknown} }

// Int returns an integer value.
func Int(v int64) Value { return Value{Kind: ValueInt, I: v} }

// Bool returns a boolean value.
func Bool(v bool) Value { return Value{Kind: ValueBool, B: v} }

// Str returns a string value.
func Str(v string) Value { return Value{Kind: ValueString, S: v} }

// IsUnknown reports whether the value is unknown.
func (v Value) IsUnknown() bool { return v.Kind == ValueUnknown }

// Truth converts the value to a three-valued truth result: Bool values
// map to themselves; every other kind is Unknown.
func (v Value) Truth() tri { return toTri(v) }

// String renders the value for diagnostics and evidence notes.
func (v Value) String() string {
	switch v.Kind {
	case ValueInt:
		return strconv.FormatInt(v.I, 10)
	case ValueBool:
		if v.B {
			return "true"
		}
		return "false"
	case ValueString:
		return strconv.Quote(v.S)
	default:
		return "<unknown>"
	}
}

// valueFromSemantic extracts the best-effort contract-domain value of a
// semantic value. Only compile-time constants yield concrete values;
// everything else is Unknown. Constant extraction is intentionally
// best-effort: it parses the frontend's display name, so exotic
// literal forms degrade to Unknown rather than failing.
func valueFromSemantic(v *semantic.Value) Value {
	if v == nil {
		return Unknown()
	}
	if v.Kind != semantic.ValueConst {
		return Unknown()
	}
	return parseConstText(v.Name, v.Type)
}

// parseConstText interprets a frontend constant rendering. Frontends
// may decorate literals with a type suffix (go/ssa renders
// "1:int", `"foo":string`), so candidates are tried with and without
// the last ":suffix". Handles decimal integers, booleans, quoted
// strings, and integral floats. Anything else is Unknown.
func parseConstText(name string, t *semantic.Type) Value {
	name = strings.TrimSpace(name)
	if name == "" {
		return Unknown()
	}
	candidates := []string{name}
	if i := strings.LastIndex(name, ":"); i > 0 {
		candidates = append(candidates, strings.TrimSpace(name[:i]))
	}
	for _, c := range candidates {
		if v, ok := parseConstBare(c); ok {
			return v
		}
	}
	return Unknown()
}

func parseConstBare(name string) (Value, bool) {
	if n, err := strconv.ParseInt(name, 0, 64); err == nil {
		return Int(n), true
	}
	if name == "true" || name == "false" {
		return Bool(name == "true"), true
	}
	if len(name) >= 2 && name[0] == '"' && name[len(name)-1] == '"' {
		if s, err := strconv.Unquote(name); err == nil {
			return Str(s), true
		}
		return Str(name[1 : len(name)-1]), true
	}
	if f, err := strconv.ParseFloat(name, 64); err == nil && f == float64(int64(f)) {
		return Int(int64(f)), true
	}
	return Unknown(), false
}
