package statemachine

import "testing"

func evalExprStr(t *testing.T, src string, lookup func(string) Value, args []Value) Value {
	t.Helper()
	e, err := parseExpr(src)
	if err != nil {
		t.Fatalf("parseExpr(%q): %v", src, err)
	}
	env := &evalEnv{
		lookup: func(n string) Value {
			if lookup != nil {
				return lookup(n)
			}
			return Unknown()
		},
		arg: func(n int) Value {
			if n >= 0 && n < len(args) {
				return args[n]
			}
			return Unknown()
		},
	}
	return e.eval(env)
}

func TestExprArithmetic(t *testing.T) {
	lookup := func(n string) Value {
		if n == "attempts" {
			return Int(4)
		}
		return Unknown()
	}
	for src, want := range map[string]Value{
		"1 + 2 * 3": Int(7), "(1 + 2) * 3": Int(9), "10 / 3": Int(3),
		"10 % 3": Int(1), "-5 + 2": Int(-3), "attempts + 1": Int(5),
	} {
		if v := evalExprStr(t, src, lookup, nil); v != want {
			t.Fatalf("%s = %v, want %v", src, v, want)
		}
	}
	if v := evalExprStr(t, "10 / 0", nil, nil); v.Kind != ValueUnknown {
		t.Fatalf("div by zero should be unknown, got %v", v)
	}
}

func TestExprComparisons(t *testing.T) {
	if v := evalExprStr(t, "attempts < 3", func(n string) Value { return Int(2) }, nil); v != Bool(true) {
		t.Fatalf("2<3 = %v", v)
	}
	if v := evalExprStr(t, "attempts < 3", func(n string) Value { return Unknown() }, nil); v.Kind != ValueUnknown {
		t.Fatalf("unknown < 3 should be unknown, got %v", v)
	}
	if v := evalExprStr(t, "x == y", func(n string) Value {
		if n == "x" {
			return Int(1)
		}
		return Unknown()
	}, nil); v.Kind != ValueUnknown {
		t.Fatalf("1 == unknown should be unknown, got %v", v)
	}
	if v := evalExprStr(t, "flag && attempts > 0", func(n string) Value {
		if n == "flag" {
			return Bool(true)
		}
		return Int(5)
	}, nil); v != Bool(true) {
		t.Fatalf("true && 5>0 = %v", v)
	}
	if v := evalExprStr(t, "flag || other", func(n string) Value {
		if n == "flag" {
			return Bool(false)
		}
		return Unknown()
	}, nil); v.Kind != ValueUnknown {
		t.Fatalf("false || unknown should be unknown, got %v", v)
	}
	if v := evalExprStr(t, "!flag", func(n string) Value { return Bool(true) }, nil); v != Bool(false) {
		t.Fatalf("!true = %v", v)
	}
}

func TestExprArgs(t *testing.T) {
	args := []Value{Int(41), Str("hi")}
	if v := evalExprStr(t, "arg[0] + 1", nil, args); v != Int(42) {
		t.Fatalf("arg[0]+1 = %v", v)
	}
	if v := evalExprStr(t, "arg[5]", nil, args); v.Kind != ValueUnknown {
		t.Fatalf("arg[5] should be unknown, got %v", v)
	}
}

func TestExprParseErrors(t *testing.T) {
	for _, src := range []string{"", "1 +", "(1", "foo(", "arg[x]", "a === b"} {
		if _, err := parseExpr(src); err == nil {
			t.Fatalf("parseExpr(%q) should fail", src)
		}
	}
}
