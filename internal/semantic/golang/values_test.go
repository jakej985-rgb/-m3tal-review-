package golang

import (
	"context"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

var valueFixtureFiles = map[string]string{
	"go.mod": "module example.com/values\n\ngo 1.23\n",
	"main.go": `package main

var GlobalCounter int

type Point struct{ F int }

func source() string { return "tainted" }

func sink(s string) { println(s) }

func process() {
	x := source()
	y := x + "!"
	sink(y)
}

func closure() func() string {
	captured := "cap"
	return func() string { return captured }
}

func phiDemo(b bool) int {
	v := 0
	if b {
		v = 1
	} else {
		v = 2
	}
	return v
}

func collections() {
	m := map[string]int{}
	m["k"] = 1
	println(m["k"])
	s := []int{1, 2}
	println(s[0])
	p := Point{}
	p.F = 3
	println(p.F)
}

func main() {
	GlobalCounter = 1
	process()
	f := closure()
	println(f())
	println(phiDemo(true))
	collections()
}
`,
}

func loadValueFixture(t *testing.T) *semantic.Program {
	t.Helper()
	dir := writeModule(t, valueFixtureFiles)
	prog, err := Load(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return prog
}

func allModelInstructions(prog *semantic.Program) []*semantic.Instruction {
	var out []*semantic.Instruction
	for _, p := range prog.Packages {
		for _, fn := range p.Functions {
			for _, b := range fn.Blocks {
				out = append(out, b.Instructions...)
			}
		}
	}
	return out
}

func TestEveryOperandResolves(t *testing.T) {
	prog := loadValueFixture(t)
	if len(prog.Values) == 0 {
		t.Fatal("no values modeled")
	}
	for _, instr := range allModelInstructions(prog) {
		for _, op := range instr.Operands {
			if op == nil || op.ID == "" {
				t.Fatalf("operand with missing identity in %v", instr)
			}
			if op.Kind == semantic.ValueUnresolved {
				t.Fatalf("unresolved operand %q (%s) in function %s", op.Name, op.Type.Text, instrDetail(instr))
			}
		}
	}
	// Program.Value indexes every modeled value.
	for _, v := range prog.Values {
		if prog.Value(v.ID) != v {
			t.Fatalf("Program.Value(%q) mismatch", v.ID)
		}
	}
}

func instrDetail(i *semantic.Instruction) string {
	if i == nil {
		return "<nil>"
	}
	return i.Detail
}

func TestValueKinds(t *testing.T) {
	prog := loadValueFixture(t)

	sink := prog.Function("example.com/values.sink")
	if sink == nil {
		t.Fatal("sink function not found")
	}
	var param *semantic.Value
	for _, v := range sink.Values {
		if v.Kind == semantic.ValueParam {
			param = v
		}
	}
	if param == nil {
		t.Fatal("sink has no parameter value")
	}
	if param.Owner != sink {
		t.Fatal("parameter Owner is not sink")
	}
	if !strings.HasPrefix(param.ID, sink.ID+"@") {
		t.Fatalf("parameter ID %q not scoped under %q", param.ID, sink.ID)
	}

	// The anonymous function inside closure() captures `captured`.
	var anon *semantic.Function
	for _, fn := range prog.Packages[0].Functions {
		_ = fn
	}
	for _, p := range prog.Packages {
		for _, fn := range p.Functions {
			if fn.Kind == semantic.FuncClosure {
				anon = fn
			}
		}
	}
	if anon == nil {
		t.Fatal("no closure function found")
	}
	var fv *semantic.Value
	for _, v := range anon.Values {
		if v.Kind == semantic.ValueFreeVar {
			fv = v
		}
	}
	if fv == nil {
		t.Fatal("closure has no free variable value")
	}
	if fv.Owner != anon {
		t.Fatal("free variable Owner is not the closure")
	}

	// GlobalCounter store/load uses a ValueGlobal.
	var glob *semantic.Value
	for _, v := range prog.Values {
		if v.Kind == semantic.ValueGlobal && v.Name == "GlobalCounter" {
			glob = v
		}
	}
	if glob == nil {
		t.Fatal("no ValueGlobal for GlobalCounter")
	}
	if glob.Package == nil || glob.Package.Path != "example.com/values" {
		t.Fatalf("global package = %+v", glob.Package)
	}

	// A phi node in phiDemo produces a ValueInstr.
	phi := prog.Function("example.com/values.phiDemo")
	var phiVal *semantic.Value
	for _, b := range phi.Blocks {
		for _, in := range b.Instructions {
			if in.Op == semantic.OpPhi && len(in.Outputs) == 1 {
				phiVal = in.Outputs[0]
			}
		}
	}
	if phiVal == nil {
		t.Fatal("no phi instruction output found")
	}
	if phiVal.Kind != semantic.ValueInstr || phiVal.Def == nil {
		t.Fatalf("phi output kind=%v def=%v", phiVal.Kind, phiVal.Def)
	}

	// Constants appear as ValueConst operands (e.g. the "!" literal).
	var konst *semantic.Value
	for _, v := range prog.Values {
		if v.Kind == semantic.ValueConst {
			konst = v
			break
		}
	}
	if konst == nil {
		t.Fatal("no ValueConst found")
	}
}

func TestDefUseChain(t *testing.T) {
	prog := loadValueFixture(t)

	process := prog.Function("example.com/values.process")
	if process == nil {
		t.Fatal("process not found")
	}
	// Find the sink call site and its argument value.
	var sinkCall *semantic.Call
	for _, c := range process.Calls {
		if strings.Contains(c.Target, "sink") {
			sinkCall = c
		}
	}
	if sinkCall == nil {
		t.Fatal("sink call not found")
	}
	ops := sinkCall.Site.Operands
	if len(ops) == 0 {
		t.Fatal("sink call has no operands")
	}
	arg := ops[len(ops)-1]
	if arg.Def == nil {
		t.Fatalf("sink argument %q has no Def", arg.ID)
	}

	// Uses(arg) must include the sink call instruction.
	uses := prog.Uses(arg)
	foundUse := false
	for _, u := range uses {
		if u == sinkCall.Site {
			foundUse = true
		}
	}
	if !foundUse {
		t.Fatal("prog.Uses does not report the sink call as a use")
	}

	// Walk definitions backwards from the sink argument; we must reach
	// the source() call instruction.
	reachedSource := false
	visited := map[*semantic.Value]bool{}
	var walk func(v *semantic.Value)
	walk = func(v *semantic.Value) {
		if v == nil || visited[v] {
			return
		}
		visited[v] = true
		def := v.Def
		if def == nil {
			return
		}
		for _, c := range process.Calls {
			if c.Site == def && strings.Contains(c.Target, "source") {
				reachedSource = true
			}
		}
		for _, op := range def.Operands {
			walk(op)
		}
	}
	walk(arg)
	if !reachedSource {
		t.Fatal("backward def walk from sink arg never reached source() call")
	}

	// Distinct SSA values keep distinct identities even when their
	// display names collide: collect duplicate Names among Values.
	byName := map[string]int{}
	for _, v := range prog.Values {
		if v.Name != "" {
			byName[v.Name]++
		}
	}
	dup := false
	for _, v := range prog.Values {
		if v.Name != "" && byName[v.Name] > 1 {
			dup = true
			break
		}
	}
	if !dup {
		t.Fatal("expected at least two distinct values sharing a display name")
	}
}

func TestDeterministicValueIDs(t *testing.T) {
	dir := writeModule(t, valueFixtureFiles)
	ctx := context.Background()
	p1, err := Load(ctx, Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := Load(ctx, Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	snap := func(p *semantic.Program) []string {
		var out []string
		for _, v := range p.Values {
			out = append(out, v.ID+"|"+string(rune(v.Kind))+"|"+v.Name)
		}
		return out
	}
	if len(snap(p1)) != len(snap(p2)) {
		t.Fatal("value counts differ between loads")
	}
	for i := range snap(p1) {
		if snap(p1)[i] != snap(p2)[i] {
			t.Fatalf("value snapshot differs at %d: %q vs %q", i, snap(p1)[i], snap(p2)[i])
		}
	}
}
