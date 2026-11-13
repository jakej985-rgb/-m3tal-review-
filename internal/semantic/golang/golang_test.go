package golang

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// writeModule creates a temporary Go module from the given
// path → contents map and returns its root directory.
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

var fixtureFiles = map[string]string{
	"go.mod": "module example.com/semtest\n\ngo 1.23\n",
	"main.go": `package main

import "example.com/semtest/lib"

func main() {
	d := lib.Dog{}
	println(lib.Greet(d))
	println(lib.Add(1, 2))
	lib.Helper()
}
`,
	"lib/lib.go": `package lib

type Speaker interface{ Speak() string }

type Dog struct{}

func (Dog) Speak() string { return "woof" }

type Cat struct{}

func (Cat) Speak() string { return "meow" }

func Greet(s Speaker) string { return s.Speak() }

func Add[T int | float64](a, b T) T { return a + b }

func Helper() int { return 42 }
`,
	// Excluded by the "never" build constraint.
	"lib/legacy.go": "//go:build never\n\npackage lib\n\nfunc Legacy() {}\n",
}

func loadFixture(t *testing.T) *semantic.Program {
	t.Helper()
	dir := writeModule(t, fixtureFiles)
	prog, err := Load(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return prog
}

func findPackage(t *testing.T, prog *semantic.Program, path string) *semantic.Package {
	t.Helper()
	pkg := prog.Package(path)
	if pkg == nil {
		t.Fatalf("package %q not found; have %v", path, packagePaths(prog))
	}
	return pkg
}

func packagePaths(prog *semantic.Program) []string {
	var out []string
	for _, p := range prog.Packages {
		out = append(out, p.Path)
	}
	return out
}

func callTargets(fn *semantic.Function) []string {
	var out []string
	for _, c := range fn.Calls {
		out = append(out, c.Target)
	}
	return out
}

func findFunction(t *testing.T, prog *semantic.Program, id string) *semantic.Function {
	t.Helper()
	fn := prog.Function(id)
	if fn == nil {
		t.Fatalf("function %q not found", id)
	}
	return fn
}

func TestLoadMultiPackage(t *testing.T) {
	prog := loadFixture(t)

	lib := findPackage(t, prog, "example.com/semtest/lib")
	if lib.Name != "lib" {
		t.Fatalf("lib.Name = %q", lib.Name)
	}
	if len(lib.Files) != 1 || !strings.HasSuffix(lib.Files[0].Path, "lib.go") {
		t.Fatalf("lib.Files = %+v", lib.Files)
	}
	if lib.Files[0].AST == nil {
		t.Fatal("lib file AST not retained")
	}
	if lib.TypesInfo == nil {
		t.Fatal("lib TypesInfo not retained")
	}

	main := findPackage(t, prog, "example.com/semtest")
	if !main.IsCommand {
		t.Fatal("root package should be marked as command")
	}

	// The generic Add should be instantiated for the int call site.
	var instance *semantic.Function
	for _, fn := range lib.Functions {
		if strings.Contains(fn.ID, ".Add[") {
			instance = fn
		}
	}
	if instance == nil {
		t.Fatal("no instantiated Add[...] function found")
	}
	if len(instance.Blocks) == 0 {
		t.Fatal("generic instance has no basic blocks")
	}
}

func TestCallGraphStaticEdges(t *testing.T) {
	prog := loadFixture(t)

	mainFn := findFunction(t, prog, "example.com/semtest.main")
	var greetCall *semantic.Call
	for _, c := range mainFn.Calls {
		if strings.Contains(c.Target, "Greet") {
			greetCall = c
		}
	}
	if greetCall == nil {
		t.Fatalf("no call to Greet in main; calls=%v", callTargets(mainFn))
	}
	if greetCall.Dynamic {
		t.Fatal("direct call to lib.Greet marked dynamic")
	}
	if len(greetCall.Callees) != 1 || greetCall.Callees[0].Name != "Greet" {
		t.Fatalf("Greet callees = %+v", greetCall.Callees)
	}
	if greetCall.Callees[0].Package.Path != "example.com/semtest/lib" {
		t.Fatalf("Greet callee package = %q", greetCall.Callees[0].Package.Path)
	}
}

func TestCallGraphDynamicDispatch(t *testing.T) {
	prog := loadFixture(t)

	greet := findFunction(t, prog, "example.com/semtest/lib.Greet")
	if len(greet.Blocks) == 0 {
		t.Fatal("Greet has no basic blocks")
	}
	var dyn *semantic.Call
	for _, c := range greet.Calls {
		if c.Dynamic {
			dyn = c
		}
	}
	if dyn == nil {
		t.Fatalf("expected a dynamic call in Greet; calls=%v", callTargets(greet))
	}
	got := map[string]bool{}
	for _, callee := range dyn.Callees {
		if callee.Name == "Speak" && callee.Receiver != nil {
			got[callee.Receiver.Text] = true
		}
	}
	for _, want := range []string{"Dog", "Cat"} {
		found := false
		for text := range got {
			if strings.Contains(text, want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("CHA callee set missing receiver %q; got %v", want, got)
		}
	}
}

func TestSourcePositions(t *testing.T) {
	prog := loadFixture(t)

	helper := findFunction(t, prog, "example.com/semtest/lib.Helper")
	pos := helper.Position
	if !pos.Valid() {
		t.Fatal("Helper has no position")
	}
	if !strings.HasSuffix(pos.File, "lib.go") {
		t.Fatalf("Helper position file = %q", pos.File)
	}
	if pos.Line <= 0 || pos.EndLine < pos.Line {
		t.Fatalf("Helper position = %+v", pos)
	}

	// Instructions inside Helper should carry positions too.
	var withPos bool
	for _, b := range helper.Blocks {
		for _, instr := range b.Instructions {
			if instr.Position.Valid() {
				withPos = true
			}
		}
	}
	if !withPos {
		t.Fatal("no instruction in Helper has a source position")
	}
}

func TestBuildConstraintsRecorded(t *testing.T) {
	prog := loadFixture(t)

	lib := findPackage(t, prog, "example.com/semtest/lib")
	found := false
	for _, f := range lib.IgnoredFiles {
		if strings.HasSuffix(f, "legacy.go") {
			found = true
		}
	}
	if !found {
		t.Fatalf("legacy.go not recorded as ignored; ignored=%v", lib.IgnoredFiles)
	}
	var diag bool
	for _, d := range prog.Diagnostics {
		if d.Category == semantic.DiagBuildConstraint {
			diag = true
		}
	}
	if !diag {
		t.Fatal("no build-constraint diagnostic recorded")
	}
	if prog.Function("example.com/semtest/lib.Legacy") != nil {
		t.Fatal("build-constrained function should not be modeled")
	}
}

func TestTypesAndSignatures(t *testing.T) {
	prog := loadFixture(t)

	lib := findPackage(t, prog, "example.com/semtest/lib")
	typeNames := map[string]*semantic.Type{}
	for _, typ := range lib.Types {
		typeNames[typ.Name] = typ
	}
	for _, want := range []string{"Speaker", "Dog", "Cat"} {
		if typeNames[want] == nil {
			t.Fatalf("type %q not modeled; have %v", want, typeNames)
		}
	}
	if typeNames["Speaker"].Kind != semantic.TypeNamed {
		t.Fatalf("Speaker kind = %v", typeNames["Speaker"].Kind)
	}

	var add *semantic.Function
	for _, fn := range lib.Functions {
		if fn.ID == "example.com/semtest/lib.Add" {
			add = fn
		}
	}
	if add == nil {
		t.Fatal("generic Add function not found")
	}
	if add.Signature == nil || len(add.Signature.TypeParams) != 1 {
		t.Fatalf("Add signature = %+v", add.Signature)
	}
	if len(add.Signature.Params) != 2 || len(add.Signature.Results) != 1 {
		t.Fatalf("Add signature params/results = %+v", add.Signature)
	}
}

func TestMalformedPackageDiagnostics(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module example.com/bad\n\ngo 1.23\n",
		"bad.go": `package bad

func Broken() {
	this is not valid go
}
`,
	})
	prog, err := Load(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var sawParse bool
	for _, d := range prog.Diagnostics {
		if d.Category == semantic.DiagParseError || d.Category == semantic.DiagTypeError {
			sawParse = true
		}
	}
	if !sawParse {
		t.Fatalf("expected parse/type diagnostic; got %+v", prog.Diagnostics)
	}
	pkg := prog.Package("example.com/bad")
	if pkg == nil {
		t.Fatal("ill-typed package missing from model")
	}
	if !pkg.IllTyped {
		t.Fatal("package not marked IllTyped")
	}
}

func TestDeterminism(t *testing.T) {
	dir := writeModule(t, fixtureFiles)
	ctx := context.Background()
	p1, err := Load(ctx, Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := Load(ctx, Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(modelSnapshot(p1), modelSnapshot(p2)) {
		t.Fatal("two loads of the same repository produced different models")
	}
}

// modelSnapshot renders the model into a comparable string slice.
func modelSnapshot(prog *semantic.Program) []string {
	var out []string
	for _, p := range prog.Packages {
		out = append(out, "pkg:"+p.Path)
		for _, f := range p.Files {
			out = append(out, "file:"+f.Path)
		}
		for _, fn := range p.Functions {
			out = append(out, "fn:"+fn.ID)
			for _, c := range fn.Calls {
				var callees []string
				for _, callee := range c.Callees {
					callees = append(callees, callee.ID)
				}
				out = append(out, "call:"+fn.ID+"->"+c.Target+"|"+strings.Join(callees, ","))
			}
		}
	}
	for _, d := range prog.Diagnostics {
		out = append(out, "diag:"+string(d.Category)+":"+d.Message)
	}
	return out
}

func TestEmptyPattern(t *testing.T) {
	dir := writeModule(t, fixtureFiles)
	prog, err := Load(context.Background(), Options{Dir: dir, Pattern: "./lib/"})
	if err != nil {
		t.Fatal(err)
	}
	if prog.Package("example.com/semtest") != nil {
		t.Fatal("pattern ./lib/ should not include the root package")
	}
	if prog.Package("example.com/semtest/lib") == nil {
		t.Fatal("pattern ./lib/ should include the lib package")
	}
}
