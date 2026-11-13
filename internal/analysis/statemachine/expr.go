package statemachine

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// This file implements the contract expression language: a small,
// deterministic, language-neutral expression syntax used in guards,
// invariants, and transition effects. The grammar is:
//
//	expr    := orExpr
//	orExpr  := andExpr ( "||" andExpr )*
//	andExpr := cmpExpr ( "&&" cmpExpr )*
//	cmpExpr := addExpr ( ("=="|"!="|"<"|"<="|">"|">=") addExpr )?
//	addExpr := mulExpr ( ("+"|"-") mulExpr )*
//	mulExpr := unary ( ("*"|"/"|"%") unary )*
//	unary   := "!" unary | "-" unary | primary
//	primary := number | string | true | false | ident
//	        |  "arg" "[" number "]" | "self" | "(" expr ")"
//
// Identifiers resolve against the contract's declared fields and
// inputs (see docs/statemachine-contracts.md). `arg[N]` reads the Nth
// aligned call argument of the triggering event; `self` reads the
// subject argument. All operations use three-valued logic: any
// operand that is Unknown makes the result Unknown.

// tri is a three-valued truth result.
type tri int

const (
	triFalse tri = iota
	triTrue
	triUnknown
)

func toTri(v Value) tri {
	if v.Kind != ValueBool {
		return triUnknown
	}
	if v.B {
		return triTrue
	}
	return triFalse
}

func (t tri) not() tri {
	switch t {
	case triTrue:
		return triFalse
	case triFalse:
		return triTrue
	default:
		return triUnknown
	}
}

func (t tri) and(o tri) tri {
	if t == triFalse || o == triFalse {
		return triFalse
	}
	if t == triTrue && o == triTrue {
		return triTrue
	}
	return triUnknown
}

func (t tri) or(o tri) tri {
	if t == triTrue || o == triTrue {
		return triTrue
	}
	if t == triFalse && o == triFalse {
		return triFalse
	}
	return triUnknown
}

// expr is a parsed contract expression.
type expr interface {
	eval(env *evalEnv) Value
	// refs appends the field/input names the expression reads.
	refs(out map[string]bool)
	String() string
}

// evalEnv resolves names and call arguments during evaluation.
type evalEnv struct {
	// lookup resolves a declared field or input name.
	lookup func(name string) Value
	// arg resolves the Nth aligned call argument.
	arg func(n int) Value
	// self resolves the subject argument.
	self func() Value
}

// ---------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokNumber
	tokString
	tokIdent
	tokOp
	tokLParen
	tokRParen
	tokLBracket
	tokRBracket
)

type token struct {
	kind tokenKind
	text string
}

func lexExpr(src string) ([]token, error) {
	var toks []token
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case unicode.IsSpace(rune(c)):
			i++
		case c == '(':
			toks = append(toks, token{tokLParen, "("})
			i++
		case c == ')':
			toks = append(toks, token{tokRParen, ")"})
			i++
		case c == '[':
			toks = append(toks, token{tokLBracket, "["})
			i++
		case c == ']':
			toks = append(toks, token{tokRBracket, "]"})
			i++
		case c == '"' || c == '\'':
			j := i + 1
			for j < len(src) && src[j] != c {
				j++
			}
			if j >= len(src) {
				return nil, fmt.Errorf("unterminated string literal")
			}
			toks = append(toks, token{tokString, src[i+1 : j]})
			i = j + 1
		case unicode.IsDigit(rune(c)):
			j := i
			for j < len(src) && (unicode.IsDigit(rune(src[j])) || src[j] == '.') {
				j++
			}
			toks = append(toks, token{tokNumber, src[i:j]})
			i = j
		case unicode.IsLetter(rune(c)) || c == '_':
			j := i
			for j < len(src) && (unicode.IsLetter(rune(src[j])) || unicode.IsDigit(rune(src[j])) || src[j] == '_') {
				j++
			}
			toks = append(toks, token{tokIdent, src[i:j]})
			i = j
		default:
			// Operators: two-character first, then single-char.
			two := ""
			if i+1 < len(src) {
				two = src[i : i+2]
			}
			switch two {
			case "==", "!=", "<=", ">=", "&&", "||":
				toks = append(toks, token{tokOp, two})
				i += 2
				continue
			}
			switch c {
			case '+', '-', '*', '/', '%', '<', '>', '!', '=':
				toks = append(toks, token{tokOp, string(c)})
				i++
			default:
				return nil, fmt.Errorf("unexpected character %q", string(c))
			}
		}
	}
	toks = append(toks, token{tokEOF, ""})
	return toks, nil
}

// ---------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------

type parser struct {
	toks []token
	pos  int
}

func parseExpr(src string) (expr, error) {
	toks, err := lexExpr(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	e, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("unexpected trailing token %q", p.peek().text)
	}
	return e, nil
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token { t := p.toks[p.pos]; p.pos++; return t }

func (p *parser) acceptOp(ops ...string) (string, bool) {
	t := p.peek()
	if t.kind == tokOp {
		for _, op := range ops {
			if t.text == op {
				p.next()
				return op, true
			}
		}
	}
	return "", false
}

func (p *parser) parseOr() (expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		if _, ok := p.acceptOp("||"); !ok {
			return left, nil
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &binExpr{op: "||", left: left, right: right}
	}
}

func (p *parser) parseAnd() (expr, error) {
	left, err := p.parseCmp()
	if err != nil {
		return nil, err
	}
	for {
		if _, ok := p.acceptOp("&&"); !ok {
			return left, nil
		}
		right, err := p.parseCmp()
		if err != nil {
			return nil, err
		}
		left = &binExpr{op: "&&", left: left, right: right}
	}
}

var cmpOps = map[string]bool{
	"==": true, "!=": true, "<": true, "<=": true, ">": true, ">=": true,
}

func (p *parser) parseCmp() (expr, error) {
	left, err := p.parseAdd()
	if err != nil {
		return nil, err
	}
	t := p.peek()
	if t.kind == tokOp && cmpOps[t.text] {
		p.next()
		right, err := p.parseAdd()
		if err != nil {
			return nil, err
		}
		return &binExpr{op: t.text, left: left, right: right}, nil
	}
	return left, nil
}

func (p *parser) parseAdd() (expr, error) {
	left, err := p.parseMul()
	if err != nil {
		return nil, err
	}
	for {
		op, ok := p.acceptOp("+", "-")
		if !ok {
			return left, nil
		}
		right, err := p.parseMul()
		if err != nil {
			return nil, err
		}
		left = &binExpr{op: op, left: left, right: right}
	}
}

func (p *parser) parseMul() (expr, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		op, ok := p.acceptOp("*", "/", "%")
		if !ok {
			return left, nil
		}
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &binExpr{op: op, left: left, right: right}
	}
}

func (p *parser) parseUnary() (expr, error) {
	if op, ok := p.acceptOp("!", "-"); ok {
		e, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &unaryExpr{op: op, operand: e}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (expr, error) {
	t := p.next()
	switch t.kind {
	case tokNumber:
		if strings.Contains(t.text, ".") {
			f, err := strconv.ParseFloat(t.text, 64)
			if err != nil {
				return nil, fmt.Errorf("bad number %q", t.text)
			}
			if f == float64(int64(f)) {
				return &litExpr{val: Int(int64(f))}, nil
			}
			return &litExpr{val: Unknown()}, nil
		}
		n, err := strconv.ParseInt(t.text, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad integer %q", t.text)
		}
		return &litExpr{val: Int(n)}, nil
	case tokString:
		return &litExpr{val: Str(t.text)}, nil
	case tokLParen:
		e, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.next().kind != tokRParen {
			return nil, fmt.Errorf("missing )")
		}
		return e, nil
	case tokIdent:
		switch t.text {
		case "true":
			return &litExpr{val: Bool(true)}, nil
		case "false":
			return &litExpr{val: Bool(false)}, nil
		case "self":
			return &nameExpr{name: "self", self: true}, nil
		case "arg":
			// arg[N]
			if p.peek().kind != tokLBracket {
				return nil, fmt.Errorf("arg must be followed by [N]")
			}
			p.next()
			idx, err := p.parsePrimary()
			if err != nil {
				return nil, err
			}
			lit, ok := idx.(*litExpr)
			if !ok || lit.val.Kind != ValueInt || lit.val.I < 0 {
				return nil, fmt.Errorf("arg index must be a non-negative integer literal")
			}
			if p.next().kind != tokRBracket {
				return nil, fmt.Errorf("arg[N] missing ]")
			}
			return &argExpr{index: idx}, nil
		}
		return &nameExpr{name: t.text}, nil
	}
	return nil, fmt.Errorf("unexpected token %q", t.text)
}

// ---------------------------------------------------------------------
// AST nodes
// ---------------------------------------------------------------------

type litExpr struct{ val Value }

func (e *litExpr) eval(*evalEnv) Value  { return e.val }
func (e *litExpr) refs(map[string]bool) {}
func (e *litExpr) String() string       { return e.val.String() }

type nameExpr struct {
	name string
	self bool
}

func (e *nameExpr) eval(env *evalEnv) Value {
	if e.self {
		if env.self != nil {
			return env.self()
		}
		return Unknown()
	}
	if env.lookup != nil {
		return env.lookup(e.name)
	}
	return Unknown()
}

func (e *nameExpr) refs(out map[string]bool) {
	if !e.self {
		out[e.name] = true
	}
}

func (e *nameExpr) String() string {
	if e.self {
		return "self"
	}
	return e.name
}

type argExpr struct{ index expr }

func (e *argExpr) eval(env *evalEnv) Value {
	if env.arg == nil {
		return Unknown()
	}
	v := e.index.eval(env)
	if v.Kind != ValueInt {
		return Unknown()
	}
	if v.I < 0 {
		return Unknown()
	}
	return env.arg(int(v.I))
}

func (e *argExpr) refs(out map[string]bool) { e.index.refs(out) }
func (e *argExpr) String() string {
	return "arg[" + e.index.String() + "]"
}

type unaryExpr struct {
	op      string
	operand expr
}

func (e *unaryExpr) eval(env *evalEnv) Value {
	v := e.operand.eval(env)
	switch e.op {
	case "!":
		t := toTri(v).not()
		if t == triUnknown {
			return Unknown()
		}
		return Bool(t == triTrue)
	case "-":
		if v.Kind == ValueInt {
			return Int(-v.I)
		}
		return Unknown()
	}
	return Unknown()
}

func (e *unaryExpr) refs(out map[string]bool) { e.operand.refs(out) }
func (e *unaryExpr) String() string           { return e.op + "(" + e.operand.String() + ")" }

type binExpr struct {
	op          string
	left, right expr
}

func (e *binExpr) eval(env *evalEnv) Value {
	l := e.left.eval(env)
	r := e.right.eval(env)
	switch e.op {
	case "&&":
		t := toTri(l).and(toTri(r))
		if t == triUnknown {
			return Unknown()
		}
		return Bool(t == triTrue)
	case "||":
		t := toTri(l).or(toTri(r))
		if t == triUnknown {
			return Unknown()
		}
		return Bool(t == triTrue)
	case "==", "!=":
		if l.Kind == ValueUnknown || r.Kind == ValueUnknown {
			return Unknown()
		}
		eq := valuesEqual(l, r)
		if e.op == "==" {
			return Bool(eq)
		}
		return Bool(!eq)
	}
	// Ordering and arithmetic require concrete ints.
	if l.Kind != ValueInt || r.Kind != ValueInt {
		return Unknown()
	}
	switch e.op {
	case "+":
		return Int(l.I + r.I)
	case "-":
		return Int(l.I - r.I)
	case "*":
		return Int(l.I * r.I)
	case "/":
		if r.I == 0 {
			return Unknown()
		}
		return Int(l.I / r.I)
	case "%":
		if r.I == 0 {
			return Unknown()
		}
		return Int(l.I % r.I)
	case "<":
		return Bool(l.I < r.I)
	case "<=":
		return Bool(l.I <= r.I)
	case ">":
		return Bool(l.I > r.I)
	case ">=":
		return Bool(l.I >= r.I)
	}
	return Unknown()
}

func (e *binExpr) refs(out map[string]bool) {
	e.left.refs(out)
	e.right.refs(out)
}

func (e *binExpr) String() string {
	return "(" + e.left.String() + " " + e.op + " " + e.right.String() + ")"
}

// valuesEqual compares two values; Unknown never equals anything,
// including itself.
func valuesEqual(a, b Value) bool {
	if a.Kind == ValueUnknown || b.Kind == ValueUnknown || a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case ValueInt:
		return a.I == b.I
	case ValueBool:
		return a.B == b.B
	case ValueString:
		return a.S == b.S
	}
	return false
}

// exprRefs returns the sorted set of field/input names an expression
// reads (excluding arg[N] indices, self, and literals).
func exprRefs(e expr) []string {
	set := make(map[string]bool)
	e.refs(set)
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
