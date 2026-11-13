package flow

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic/golang"
)

// writeModule creates a temporary Go module from the given
// path → contents map and returns its root directory. It mirrors the
// helper in internal/semantic/golang tests (which is package-private).
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for path, contents := range files {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// loadProgram loads a synthetic module into a semantic.Program.
func loadProgram(t testing.TB, files map[string]string) *semantic.Program {
	t.Helper()
	dir := t.TempDir()
	for path, contents := range files {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prog, err := golang.Load(context.Background(), golang.Options{Dir: dir})
	if err != nil {
		t.Fatalf("golang.Load: %v", err)
	}
	for _, d := range prog.Diagnostics {
		if d.Severity == semantic.SeverityError {
			t.Fatalf("load diagnostic: %s: %s", d.Category, d.Message)
		}
	}
	return prog
}

func analyze(t *testing.T, prog *semantic.Program, opts Options) *Result {
	t.Helper()
	a := NewAnalyzer(prog, opts)
	return a.Analyze(context.Background())
}

func summaryOf(t *testing.T, res *Result, fnID string) *Summary {
	t.Helper()
	s := res.Summaries[fnID]
	if s == nil {
		t.Fatalf("no summary for %s (have %d)", fnID, len(res.Summaries))
	}
	return s
}

func hasOrigin(os []Origin, o Origin) bool {
	for _, x := range os {
		if x == o {
			return true
		}
	}
	return false
}

func hasPlace(ps []Place, p Place) bool {
	for _, x := range ps {
		if x == p {
			return true
		}
	}
	return false
}

func hasWrite(ws []Write, p Place) bool {
	for _, w := range ws {
		if w.Target == p {
			return true
		}
	}
	return false
}

const flowFixture = `module flowtest

go 1.23
`

// TestCrossPackageFlow verifies that parameter/return facts propagate
// through helper calls across package boundaries using semantic value
// identities (param indices), not display names.
func TestCrossPackageFlow(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": flowFixture,
		"lib/a.go": `package lib

func Double(x int) int { return x * 2 }

func Wrap(x int) int { return Double(x) + 1 }
`,
		"app/b.go": `package app

import "flowtest/lib"

func Process(x int) int { return lib.Wrap(x) }

func Run(y int) int {
	z := Process(y)
	return z
}
`,
	})
	res := analyze(t, prog, Options{})

	// Leaf helper: returns its parameter.
	double := summaryOf(t, res, "flowtest/lib.Double")
	if len(double.Returns) != 1 || !hasOrigin(double.Returns[0], Origin{Kind: OriginParam, Index: 0}) {
		t.Fatalf("Double.Returns = %+v, want param 0", double.Returns)
	}

	// Mid helper: its return depends on its own param 0, propagated
	// through the Double call.
	wrap := summaryOf(t, res, "flowtest/lib.Wrap")
	if len(wrap.Returns) != 1 || !hasOrigin(wrap.Returns[0], Origin{Kind: OriginParam, Index: 0}) {
		t.Fatalf("Wrap.Returns = %+v, want param 0", wrap.Returns)
	}

	// Cross-package caller: Process returns lib.Wrap's result, which
	// depends on Process's param 0.
	process := summaryOf(t, res, "flowtest/app.Process")
	if len(process.Returns) != 1 || !hasOrigin(process.Returns[0], Origin{Kind: OriginParam, Index: 0}) {
		t.Fatalf("Process.Returns = %+v, want param 0", process.Returns)
	}

	// Two levels up: Run's call to Process yields a result depending
	// on Run's param 0.
	run := summaryOf(t, res, "flowtest/app.Run")
	var callToProcess *CallFact
	for _, c := range run.Calls {
		if strings.Contains(c.Target, "Process") {
			callToProcess = c
		}
	}
	if callToProcess == nil {
		t.Fatalf("Run has no call to Process; calls = %+v", run.Calls)
	}
	if len(callToProcess.Callees) != 1 || callToProcess.Callees[0] != "flowtest/app.Process" {
		t.Fatalf("Process call callees = %v", callToProcess.Callees)
	}
	if len(callToProcess.Results) == 0 || !hasOrigin(callToProcess.Results[0], Origin{Kind: OriginParam, Index: 0}) {
		t.Fatalf("call results = %+v, want Run param 0", callToProcess.Results)
	}
}

// TestDefUseChains verifies intra-procedural propagation through
// assignments, branches, and phi nodes.
func TestDefUseChains(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": flowFixture,
		"flowtest.go": `package main

func Max2(a, b int) int {
	m := a
	if b > a {
		m = b
	}
	return m
}

func Select(x int, c bool) int {
	if c {
		return x + 1
	}
	return x - 1
}

func main() {
	println(Max2(1, 2), Select(3, true))
}
`,
	})
	res := analyze(t, prog, Options{})

	max2 := summaryOf(t, res, "flowtest.Max2")
	if len(max2.Returns) != 1 {
		t.Fatalf("Max2.Returns len = %d", len(max2.Returns))
	}
	// The phi-merged value depends on both parameters.
	if !hasOrigin(max2.Returns[0], Origin{Kind: OriginParam, Index: 0}) ||
		!hasOrigin(max2.Returns[0], Origin{Kind: OriginParam, Index: 1}) {
		t.Fatalf("Max2.Returns[0] = %+v, want params 0 and 1", max2.Returns[0])
	}

	sel := summaryOf(t, res, "flowtest.Select")
	if len(sel.Returns) != 1 || !hasOrigin(sel.Returns[0], Origin{Kind: OriginParam, Index: 0}) {
		t.Fatalf("Select.Returns = %+v, want param 0", sel.Returns)
	}
}

// TestSideEffects verifies read/write summaries for globals and
// pointer-receiver fields.
func TestSideEffects(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": flowFixture,
		"flowtest.go": `package main

var count int

type Counter struct{ n int }

func Inc() { count++ }

func Read() int { return count }

func (c *Counter) Set(n int) { c.n = n }

func (c *Counter) Get() int { return c.n }

func main() {
	Inc()
	println(Read())
	c := &Counter{}
	c.Set(41)
	println(c.Get())
}
`,
	})
	res := analyze(t, prog, Options{})

	inc := summaryOf(t, res, "flowtest.Inc")
	var globalPlace Place
	for _, w := range inc.Writes {
		if w.Target.Kind == PlaceGlobal {
			globalPlace = w.Target
		}
	}
	if globalPlace.Kind != PlaceGlobal || !strings.Contains(globalPlace.ID, "count") {
		t.Fatalf("Inc.Writes = %+v, want a global write to count", inc.Writes)
	}
	read := summaryOf(t, res, "flowtest.Read")
	found := false
	for _, p := range read.Reads {
		if p.Kind == PlaceGlobal && strings.Contains(p.ID, "count") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Read.Reads = %+v, want global count", read.Reads)
	}
	if len(read.Returns) != 1 {
		t.Fatalf("Read.Returns = %+v", read.Returns)
	}
	foundOrigin := false
	for _, o := range read.Returns[0] {
		if o.Kind == OriginGlobal && strings.Contains(o.ID, "count") {
			foundOrigin = true
		}
	}
	if !foundOrigin {
		t.Fatalf("Read.Returns[0] = %+v, want global count origin", read.Returns[0])
	}

	set := summaryOf(t, res, "(*flowtest.Counter).Set")
	found = false
	for _, w := range set.Writes {
		if w.Target.Kind == PlaceParam && w.Target.Index == 0 {
			found = true
			if !hasOrigin(w.Sources, Origin{Kind: OriginParam, Index: 1}) {
				t.Fatalf("Set write sources = %+v, want param 1 (n)", w.Sources)
			}
		}
	}
	if !found {
		t.Fatalf("Set.Writes = %+v, want write through param 0 (receiver)", set.Writes)
	}

	get := summaryOf(t, res, "(*flowtest.Counter).Get")
	found = false
	for _, p := range get.Reads {
		if p.Kind == PlaceParam && p.Index == 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("Get.Reads = %+v, want read of param 0 (receiver)", get.Reads)
	}
	if len(get.Returns) != 1 || !hasOrigin(get.Returns[0], Origin{Kind: OriginParam, Index: 0}) {
		t.Fatalf("Get.Returns = %+v, want param 0", get.Returns)
	}
}

// TestInterfaceDispatch verifies CHA may-set propagation: an interface
// call records all concrete callees and unions their return facts.
func TestInterfaceDispatch(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": flowFixture,
		"flowtest.go": `package main

type Speaker interface{ Greet() string }

type Dog struct{ name string }
type Cat struct{ name string }

func (d Dog) Greet() string { return d.name }
func (c Cat) Greet() string { return c.name }

func Speak(s Speaker) string { return s.Greet() }

func main() {
	d := Dog{name: "rex"}
	c := Cat{name: "tom"}
	println(Speak(d), Speak(c))
}
`,
	})
	res := analyze(t, prog, Options{})

	speak := summaryOf(t, res, "flowtest.Speak")
	if len(speak.Calls) != 1 {
		t.Fatalf("Speak.Calls len = %d, want 1", len(speak.Calls))
	}
	call := speak.Calls[0]
	if !call.Dynamic {
		t.Fatalf("interface call should be Dynamic")
	}
	if len(call.Callees) < 2 {
		t.Fatalf("Speak call callees = %v, want at least Dog.Greet and Cat.Greet", call.Callees)
	}
	var sawDog, sawCat bool
	for _, id := range call.Callees {
		if strings.Contains(id, "Dog") && strings.Contains(id, "Greet") {
			sawDog = true
		}
		if strings.Contains(id, "Cat") && strings.Contains(id, "Greet") {
			sawCat = true
		}
	}
	if !sawDog || !sawCat {
		t.Fatalf("Speak call callees = %v, want Dog.Greet and Cat.Greet may-set", call.Callees)
	}
	// Both implementations return their receiver's name field, i.e.
	// param 0; mapped through the interface receiver the result
	// depends on Speak's param 0.
	if len(call.Results) == 0 || !hasOrigin(call.Results[0], Origin{Kind: OriginParam, Index: 0}) {
		t.Fatalf("Speak call results = %+v, want param 0", call.Results)
	}
	if len(speak.Returns) != 1 || !hasOrigin(speak.Returns[0], Origin{Kind: OriginParam, Index: 0}) {
		t.Fatalf("Speak.Returns = %+v, want param 0", speak.Returns)
	}
}

// TestRecursion verifies that recursive summaries converge to a
// fixpoint without unbounded iteration.
func TestRecursion(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": flowFixture,
		"flowtest.go": `package main

func Fact(n int) int {
	if n <= 1 {
		return 1
	}
	return n * Fact(n-1)
}

func Even(n int) bool {
	if n == 0 {
		return true
	}
	return Odd(n - 1)
}

func Odd(n int) bool {
	if n == 0 {
		return false
	}
	return Even(n - 1)
}

func main() {
	println(Fact(5), Even(4), Odd(3))
}
`,
	})
	res := analyze(t, prog, Options{})
	if res.Truncated {
		t.Fatalf("analysis truncated unexpectedly: %+v", res.Diagnostics)
	}

	fact := summaryOf(t, res, "flowtest.Fact")
	if fact.Truncated {
		t.Fatalf("Fact summary truncated: %+v", fact.Reasons)
	}
	if len(fact.Returns) != 1 || !hasOrigin(fact.Returns[0], Origin{Kind: OriginParam, Index: 0}) {
		t.Fatalf("Fact.Returns = %+v, want param 0", fact.Returns)
	}
	// The recursive call site is recorded.
	var selfCall *CallFact
	for _, c := range fact.Calls {
		for _, id := range c.Callees {
			if id == "flowtest.Fact" {
				selfCall = c
			}
		}
	}
	if selfCall == nil {
		t.Fatalf("Fact has no self call; calls = %+v", fact.Calls)
	}

	// Even/Odd return booleans computed from constants and mutual
	// calls; the int parameter does not flow into the result, so
	// Returns is legitimately empty — but the mutual call edges must
	// be recorded and the fixpoint must converge.
	even := summaryOf(t, res, "flowtest.Even")
	odd := summaryOf(t, res, "flowtest.Odd")
	if even.Truncated || odd.Truncated {
		t.Fatalf("mutual recursion should converge: even=%+v odd=%+v", even.Reasons, odd.Reasons)
	}
	var sawOddCall, sawEvenCall bool
	for _, c := range even.Calls {
		for _, id := range c.Callees {
			if id == "flowtest.Odd" {
				sawOddCall = true
			}
		}
	}
	for _, c := range odd.Calls {
		for _, id := range c.Callees {
			if id == "flowtest.Even" {
				sawEvenCall = true
			}
		}
	}
	if !sawOddCall || !sawEvenCall {
		t.Fatalf("mutual call edges missing: even=%+v odd=%+v", even.Calls, odd.Calls)
	}
}

// TestUnknownCalls verifies that unresolved and external calls are
// flagged rather than silently treated as safe.
func TestUnknownCalls(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": flowFixture,
		"flowtest.go": `package main

import "os"

func Apply(f func(int) int, x int) int { return f(x) }

func CallEnv() string { return os.Getenv("HOME") }

func main() {
	println(Apply(func(v int) int { return v }, 1))
	println(CallEnv())
}
`,
	})
	res := analyze(t, prog, Options{})

	apply := summaryOf(t, res, "flowtest.Apply")
	var dyn *CallFact
	for _, c := range apply.Calls {
		if c.Dynamic {
			dyn = c
		}
	}
	if dyn == nil {
		t.Fatalf("Apply has no dynamic call; calls = %+v", apply.Calls)
	}
	if !dyn.Unknown {
		t.Fatalf("dynamic call through func param should be Unknown; fact = %+v", dyn)
	}
	if dyn.Reason == "" {
		t.Fatalf("unknown call must carry a reason")
	}
	if !apply.Unknown {
		t.Fatalf("Apply summary should be Unknown")
	}
	// The call result (if any) must be tainted.
	if len(dyn.Results) == 0 || !hasOrigin(dyn.Results[0], Origin{Kind: OriginUnknown}) {
		t.Fatalf("dynamic call results = %+v, want OriginUnknown", dyn.Results)
	}

	env := summaryOf(t, res, "flowtest.CallEnv")
	var ext *CallFact
	for _, c := range env.Calls {
		if strings.Contains(c.Target, "Getenv") {
			ext = c
		}
	}
	if ext == nil {
		t.Fatalf("CallEnv has no os.Getenv call; calls = %+v", env.Calls)
	}
	if !ext.Unknown {
		t.Fatalf("external call should be Unknown; fact = %+v", ext)
	}
	if len(env.Returns) != 1 || !hasOrigin(env.Returns[0], Origin{Kind: OriginUnknown}) {
		t.Fatalf("CallEnv.Returns = %+v, want OriginUnknown", env.Returns)
	}
}

// TestBudgetTruncation verifies that budgets are honored and reported.
func TestBudgetTruncation(t *testing.T) {
	files := map[string]string{
		"go.mod": flowFixture,
		"flowtest.go": `package main

func A(x int) int { return B(x) }
func B(x int) int { return C(x) }
func C(x int) int { return x }

func main() { println(A(1)) }
`,
	}
	prog := loadProgram(t, files)

	// MaxFunctions=1: only one function is summarized; calls to the
	// others are unknown.
	res := analyze(t, prog, Options{MaxFunctions: 1})
	if !res.Truncated {
		t.Fatalf("expected truncated result with MaxFunctions=1")
	}
	var sawUnknown bool
	for _, s := range res.Summaries {
		for _, c := range s.Calls {
			if c.Unknown {
				sawUnknown = true
			}
		}
	}
	if !sawUnknown {
		t.Fatalf("expected unknown call facts for unanalyzed callees")
	}

	// MaxRounds=1 on a recursive program must not silently converge.
	prog2 := loadProgram(t, map[string]string{
		"go.mod": flowFixture,
		"flowtest.go": `package main

func Loop(n int) int {
	if n <= 0 {
		return 0
	}
	return Loop(n - 1)
}

func main() { println(Loop(3)) }
`,
	})
	res2 := analyze(t, prog2, Options{MaxRounds: 1})
	if !res2.Truncated {
		t.Fatalf("expected truncated result with MaxRounds=1 on recursion")
	}
	loop := summaryOf(t, res2, "flowtest.Loop")
	if !loop.Truncated {
		t.Fatalf("Loop summary should be marked truncated")
	}
}

// TestFlowQuery verifies the interprocedural trace API: value
// identities are followed through parameters, arguments, and returns
// across packages.
func TestFlowQuery(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": flowFixture,
		"lib/x.go": `package lib

func Id(x int) int { return x }
`,
		"flowtest.go": `package main

import "flowtest/lib"

func Wrap(y int) int { return lib.Id(y) }

func main() {
	println(Wrap(7))
}
`,
	})
	a := NewAnalyzer(prog, Options{})
	res := a.Analyze(context.Background())
	_ = res

	// Find lib.Id's parameter value.
	idFn := prog.Function("flowtest/lib.Id")
	if idFn == nil {
		t.Fatal("lib.Id not found")
	}
	var param *semantic.Value
	for _, v := range idFn.Values {
		if v.Kind == semantic.ValueParam {
			param = v
			break
		}
	}
	if param == nil {
		t.Fatal("lib.Id has no param value")
	}

	flow := a.Flow(param)
	if len(flow.Events) < 2 {
		t.Fatalf("Flow from lib.Id param reached only %d events", len(flow.Events))
	}

	// The trace from any reached value in main.Wrap should pass
	// through the call-arg and call-result boundaries.
	var sawResult bool
	for _, e := range flow.Events {
		if e.Via == "call-result" {
			sawResult = true
		}
	}
	// lib.Id's return flows back through call sites via "call-result".
	if !sawResult {
		t.Fatalf("expected a call-result edge; events = %+v", flow.Events)
	}

	// Pick the last event (a value inside main.Wrap's call) and
	// reconstruct its trace.
	last := flow.Events[len(flow.Events)-1]
	trace := flow.Trace(last.ValueID)
	if len(trace) < 2 {
		t.Fatalf("trace too short: %+v", trace)
	}
	if trace[0].ValueID != param.ID {
		t.Fatalf("trace does not start at seed: %+v", trace)
	}
	if trace[len(trace)-1].ValueID != last.ValueID {
		t.Fatalf("trace does not end at target")
	}

	// Determinism: same query twice gives same events.
	flow2 := a.Flow(param)
	if len(flow2.Events) != len(flow.Events) {
		t.Fatalf("nondeterministic flow: %d vs %d events", len(flow.Events), len(flow2.Events))
	}
}

// BenchmarkAnalyze measures summary computation on a synthetic
// repository of moderate size.
func BenchmarkAnalyze(b *testing.B) {
	files := map[string]string{
		"go.mod": "module benchmod\n\ngo 1.23\n",
	}
	// 20 packages, each with a chain of helpers calling the previous
	// package plus local recursion-free helpers.
	for p := 0; p < 20; p++ {
		pkg := fmt.Sprintf("pkg%02d", p)
		files[pkg+"/pkg.go"] = fmt.Sprintf(`package %s

func Leaf%d(x int) int { return x + %d }

func Mid%d(x int) int {
	if x > 100 {
		return Leaf%d(x - 1)
	}
	return x * 2
}

func Top%d(x int) int { return Mid%d(Leaf%d(x)) }
`, pkg, p, p, p, p, p, p, p)
		if p > 0 {
			prev := fmt.Sprintf("pkg%02d", p-1)
			files[pkg+"/cross.go"] = fmt.Sprintf(`package %s

import "%s"

func Cross%d(x int) int { return %s.Top%d(x) + Mid%d(x) }
`, pkg, "benchmod/"+prev, p, prev, p-1, p)
		}
	}
	files["flowtest.go"] = `package main

import (
	"benchmod/pkg00"
	"benchmod/pkg19"
)

func main() {
	println(pkg00.Top0(1), pkg19.Cross19(2))
}
`
	prog := loadProgram(b, files)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a := NewAnalyzer(prog, Options{})
		a.Analyze(context.Background())
	}
}
