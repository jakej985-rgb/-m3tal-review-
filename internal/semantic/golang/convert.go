package golang

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// converter materializes semantic model objects from SSA packages and
// functions. It is single-threaded; determinism comes from sorted
// iteration and deferred sorting in semantic.Program.Sort.
type converter struct {
	prog     *semantic.Program
	ssaProg  *ssa.Program
	ssaIndex map[*packages.Package]*ssa.Package
	fset     *token.FileSet
	callMode CallGraphMode

	// modeled maps ssa packages that were part of the load set (roots)
	// to their semantic package.
	modeled map[*ssa.Package]*semantic.Package
	// rootPkgs maps each root packages.Package to its semantic package.
	rootPkgs map[*packages.Package]*semantic.Package
	// fnMap maps every materialized ssa function to its model function.
	fnMap map[*ssa.Function]*semantic.Function
	// callMap maps call-site instructions to their model Call.
	callMap map[ssa.Instruction]*semantic.Call
	// typeMemo deduplicates type conversion.
	typeMemo map[types.Type]*semantic.Type
}

func newConverter(prog *semantic.Program, ssaProg *ssa.Program, ssaIndex map[*packages.Package]*ssa.Package, fset *token.FileSet, mode CallGraphMode) *converter {
	return &converter{
		prog:     prog,
		ssaProg:  ssaProg,
		ssaIndex: ssaIndex,
		fset:     fset,
		callMode: mode,
		modeled:  make(map[*ssa.Package]*semantic.Package),
		rootPkgs: make(map[*packages.Package]*semantic.Package),
		fnMap:    make(map[*ssa.Function]*semantic.Function),
		callMap:  make(map[ssa.Instruction]*semantic.Call),
		typeMemo: make(map[types.Type]*semantic.Type),
	}
}

// registerPackage creates the semantic Package shell for a root package
// and records it in the modeled map. It must be called for every root
// before any populatePackage call so that cross-package references
// resolve to the modeled package rather than an external stub.
// Ill-typed packages get a metadata-only entry and no SSA mapping.
func (c *converter) registerPackage(p *packages.Package) *semantic.Package {
	// Test variants share PkgPath with the ordinary package; record the
	// driver's unique ID (e.g. "x [x.test]") so lookups stay distinct
	// while Path remains the import path.
	mp := &semantic.Package{
		Path:      p.PkgPath,
		ID:        variantID(p),
		Name:      p.Name,
		IsCommand: p.Name == "main",
		IllTyped:  p.IllTyped || p.Types == nil,
		Imports:   importPaths(p.Imports),
		ImportIDs: importIDs(p.Imports),
		TypesInfo: p.TypesInfo,
	}
	c.prog.Packages = append(c.prog.Packages, mp)
	c.rootPkgs[p] = mp

	// File metadata does not depend on SSA; record it for every package.
	for _, f := range p.Syntax {
		mp.Files = append(mp.Files, &semantic.File{
			Path:    c.filePath(f),
			Package: mp,
			AST:     f,
		})
	}
	mp.IgnoredFiles = append(mp.IgnoredFiles, p.IgnoredFiles...)

	if p.IllTyped || p.Types == nil {
		return mp
	}
	sp := c.ssaIndex[p]
	if sp == nil {
		c.prog.Diagnostics = append(c.prog.Diagnostics, semantic.Diagnostic{
			Severity: semantic.SeverityWarning,
			Category: semantic.DiagUnsupported,
			Message:  "SSA representation unavailable for package",
			Package:  p.PkgPath,
		})
		return mp
	}
	c.modeled[sp] = mp
	return mp
}

// packageForRoot returns the semantic package registered for root p.
func (c *converter) packageForRoot(p *packages.Package) *semantic.Package {
	return c.rootPkgs[p]
}

// populatePackage fills a registered package with functions, methods,
// and declared types. It is a no-op for ill-typed packages.
func (c *converter) populatePackage(p *packages.Package, mp *semantic.Package) {
	sp := c.ssaIndex[p]
	if sp == nil || mp.IllTyped {
		return
	}

	// Package-level functions and declared types, in sorted member
	// order for determinism.
	memberNames := make([]string, 0, len(sp.Members))
	for name := range sp.Members {
		memberNames = append(memberNames, name)
	}
	sort.Strings(memberNames)
	for _, name := range memberNames {
		switch m := sp.Members[name].(type) {
		case *ssa.Function:
			c.function(m)
		case *ssa.Type:
			if t := c.declaredType(m); t != nil {
				mp.Types = append(mp.Types, t)
			}
		}
	}

	// Methods of declared named types. Generic types are skipped here;
	// their instantiations are materialized on demand from call sites.
	for _, name := range memberNames {
		m, ok := sp.Members[name].(*ssa.Type)
		if !ok {
			continue
		}
		obj, ok := m.Object().(*types.TypeName)
		if !ok {
			continue
		}
		named, ok := obj.Type().(*types.Named)
		if !ok || named.TypeParams() != nil || types.IsInterface(named) {
			continue
		}
		c.methodsOf(named)
		c.methodsOf(types.NewPointer(named))
	}
}

// methodsOf materializes every concrete method in T's method set.
func (c *converter) methodsOf(T types.Type) {
	mset := c.ssaProg.MethodSets.MethodSet(T)
	for i := 0; i < mset.Len(); i++ {
		sel := mset.At(i)
		if sel.Obj().Pkg() == nil {
			continue
		}
		if fn := c.ssaProg.MethodValue(sel); fn != nil {
			c.function(fn)
		}
	}
}

// declaredType converts an ssa.Type member into a model Type.
func (c *converter) declaredType(t *ssa.Type) *semantic.Type {
	obj, ok := t.Object().(*types.TypeName)
	if !ok {
		return nil
	}
	return c.typeModel(obj.Type())
}

// function materializes the model Function for an ssa function,
// including its body when available. Results are memoized so recursive
// and mutually recursive references resolve to the same object.
func (c *converter) function(fn *ssa.Function) *semantic.Function {
	if mf, ok := c.fnMap[fn]; ok {
		return mf
	}

	pkg := c.packageFor(fn)
	id := functionID(fn)
	// Qualify functions of test-variant packages so IDs stay unique.
	// This also covers generic instances (fn.Pkg == nil), which
	// packageFor attributes to their origin's package variant.
	if !pkg.External && pkg.ID != "" {
		id += " [" + pkg.ID + "]"
	}
	mf := &semantic.Function{
		ID:        id,
		Name:      fn.Name(),
		Package:   pkg,
		Signature: c.signatureModel(fn.Signature),
		Position:  c.functionPos(fn),
		Synthetic: fn.Synthetic != "",
		Exported:  isExported(fn),
	}
	if r := fn.Signature.Recv(); r != nil {
		mf.Receiver = c.typeModel(r.Type())
	}
	switch {
	case fn.Synthetic != "":
		mf.Kind = semantic.FuncSynthetic
	case fn.Parent() != nil:
		mf.Kind = semantic.FuncClosure
	case isInitName(fn.Name()):
		mf.Kind = semantic.FuncInit
	case fn.Signature.Recv() != nil:
		mf.Kind = semantic.FuncMethod
	default:
		mf.Kind = semantic.FuncDecl
	}
	c.fnMap[fn] = mf
	pkg.Functions = append(pkg.Functions, mf)

	if len(fn.Blocks) > 0 {
		c.functionBody(mf, fn)
	}
	// Materialize nested function literals of analyzed packages even
	// when no call edge reaches them (e.g. callbacks passed to external
	// functions such as sort.Slice).
	if !pkg.External {
		for _, anon := range fn.AnonFuncs {
			c.function(anon)
		}
	}
	return mf
}

// functionBody converts an SSA function's basic blocks, instructions,
// and call sites.
func (c *converter) functionBody(mf *semantic.Function, fn *ssa.Function) {
	blockMap := make(map[*ssa.BasicBlock]*semantic.BasicBlock, len(fn.Blocks))
	for i, sb := range fn.Blocks {
		mb := &semantic.BasicBlock{ID: i, Index: i}
		mf.Blocks = append(mf.Blocks, mb)
		blockMap[sb] = mb
	}

	var operands [10]*ssa.Value
	nextID := 0
	for _, sb := range fn.Blocks {
		mb := blockMap[sb]
		for _, si := range sb.Instrs {
			op, detail := mapOp(si)
			mi := &semantic.Instruction{
				ID:       nextID,
				Op:       op,
				Detail:   detail,
				Position: fsetPos(c.fset, si.Pos(), token.NoPos),
			}
			for _, v := range si.Operands(operands[:0]) {
				if v == nil || *v == nil {
					continue
				}
				mi.Operands = append(mi.Operands, c.valueModel(*v))
			}
			nextID++
			mb.Instructions = append(mb.Instructions, mi)

			if ci, ok := si.(ssa.CallInstruction); ok {
				mf.Calls = append(mf.Calls, c.callModel(ci, mi))
			}
		}
		for _, succ := range sb.Succs {
			if mb2 := blockMap[succ]; mb2 != nil {
				mb.Successors = append(mb.Successors, mb2)
			}
		}
		for _, pred := range sb.Preds {
			if mb2 := blockMap[pred]; mb2 != nil {
				mb.Predecessors = append(mb.Predecessors, mb2)
			}
		}
	}
}

// valueModel converts an SSA value operand.
func (c *converter) valueModel(v ssa.Value) semantic.Value {
	return semantic.Value{
		Name: v.Name(),
		Type: c.typeModel(v.Type()),
	}
}

// packageFor returns the semantic package owning fn, creating an
// external stub package for functions outside the analyzed set.
func (c *converter) packageFor(fn *ssa.Function) *semantic.Package {
	if sp := fn.Pkg; sp != nil {
		if mp, ok := c.modeled[sp]; ok {
			return mp
		}
		return c.externalPackage(sp.Pkg.Path(), sp.Pkg.Name())
	}
	// Generic instances have no package of their own; attribute them to
	// the package of the generic origin.
	if origin := fn.Origin(); origin != nil && origin != fn {
		return c.packageFor(origin)
	}
	// Shared synthetic functions (wrappers, thunks) have no package;
	// attribute them to the receiver's package when possible.
	if pkg := receiverPackage(fn.Signature); pkg != nil {
		return c.externalPackage(pkg.Path(), pkg.Name())
	}
	return c.externalPackage("<unknown>", "<unknown>")
}

// receiverPackage returns the package that declares the receiver type of
// sig, or nil for package-level functions.
func receiverPackage(sig *types.Signature) *types.Package {
	recv := sig.Recv()
	if recv == nil {
		return nil
	}
	t := recv.Type()
	for {
		switch tt := t.(type) {
		case *types.Pointer:
			t = tt.Elem()
		case *types.Named:
			if obj := tt.Obj(); obj != nil {
				return obj.Pkg()
			}
			return nil
		default:
			return nil
		}
	}
}

// externalPackage returns the stub package for path, creating it on
// first use.
func (c *converter) externalPackage(path, name string) *semantic.Package {
	for _, p := range c.prog.Packages {
		if p.Key() == path {
			return p
		}
	}
	mp := &semantic.Package{
		Path:     path,
		Name:     name,
		External: true,
	}
	c.prog.Packages = append(c.prog.Packages, mp)
	return mp
}

// filePath returns the file name recorded in the FileSet for f.
func (c *converter) filePath(f *ast.File) string {
	if c.fset == nil {
		return ""
	}
	return c.fset.PositionFor(f.Package, false).Filename
}

// typeModel converts a go/types type into the neutral model. Results
// are memoized; named types are leaves (their underlying structure is
// available via Text), so recursion cannot cycle.
func (c *converter) typeModel(t types.Type) *semantic.Type {
	if t == nil {
		return nil
	}
	key := types.Unalias(t)
	if mt, ok := c.typeMemo[key]; ok {
		return mt
	}
	mt := &semantic.Type{Text: key.String()}
	c.typeMemo[key] = mt

	switch t := key.(type) {
	case *types.Basic:
		mt.Kind = semantic.TypeBasic
		mt.Name = t.Name()
	case *types.Named:
		mt.Kind = semantic.TypeNamed
		mt.Name = t.Obj().Name()
		if obj := t.Obj(); obj != nil && obj.Pkg() != nil {
			mt.Package = obj.Pkg().Path()
		}
		if targs := t.TypeArgs(); targs != nil && targs.Len() > 0 {
			for i := 0; i < targs.Len(); i++ {
				mt.TypeArgs = append(mt.TypeArgs, c.typeModel(targs.At(i)))
			}
		}
	case *types.Pointer:
		mt.Kind = semantic.TypePointer
		mt.Elem = c.typeModel(t.Elem())
	case *types.Slice:
		mt.Kind = semantic.TypeSlice
		mt.Elem = c.typeModel(t.Elem())
	case *types.Array:
		mt.Kind = semantic.TypeArray
		mt.Elem = c.typeModel(t.Elem())
		mt.ArrayLen = t.Len()
	case *types.Map:
		mt.Kind = semantic.TypeMap
		mt.Key = c.typeModel(t.Key())
		mt.Elem = c.typeModel(t.Elem())
	case *types.Chan:
		mt.Kind = semantic.TypeChan
		mt.Elem = c.typeModel(t.Elem())
	case *types.Signature:
		mt.Kind = semantic.TypeFunc
		mt.Signature = c.signatureModel(t)
	case *types.Struct:
		mt.Kind = semantic.TypeStruct
	case *types.Interface:
		mt.Kind = semantic.TypeInterface
	case *types.Tuple:
		mt.Kind = semantic.TypeTuple
	case *types.TypeParam:
		mt.Kind = semantic.TypeTypeParam
		mt.Name = t.Obj().Name()
	default:
		mt.Kind = semantic.TypeInvalid
	}
	return mt
}

// signatureModel converts a go/types signature.
func (c *converter) signatureModel(sig *types.Signature) *semantic.Signature {
	if sig == nil {
		return nil
	}
	ms := &semantic.Signature{Variadic: sig.Variadic()}
	if recv := sig.Recv(); recv != nil {
		ms.Recv = c.typeModel(recv.Type())
	}
	if tparams := sig.TypeParams(); tparams != nil {
		for i := 0; i < tparams.Len(); i++ {
			ms.TypeParams = append(ms.TypeParams, tparams.At(i).Obj().Name())
		}
	}
	ms.Params = c.tupleModel(sig.Params())
	ms.Results = c.tupleModel(sig.Results())
	return ms
}

// tupleModel converts a types.Tuple to a type list.
func (c *converter) tupleModel(tup *types.Tuple) []*semantic.Type {
	if tup == nil || tup.Len() == 0 {
		return nil
	}
	out := make([]*semantic.Type, 0, tup.Len())
	for i := 0; i < tup.Len(); i++ {
		out = append(out, c.typeModel(tup.At(i).Type()))
	}
	return out
}

// functionPos returns the source position of fn's declaration,
// including the end position when syntax is available.
func (c *converter) functionPos(fn *ssa.Function) semantic.Position {
	var pos, end token.Pos
	if node := fn.Syntax(); node != nil {
		pos, end = node.Pos(), node.End()
	} else {
		pos = fn.Pos()
	}
	return fsetPos(c.fset, pos, end)
}

// functionID returns a stable identifier for fn. SSA's RelString is
// already package-path qualified and distinguishes methods, closures,
// and synthetic functions.
func functionID(fn *ssa.Function) string {
	return fn.RelString(nil)
}

func isExported(fn *ssa.Function) bool {
	obj, ok := fn.Object().(*types.Func)
	return ok && obj.Exported()
}

func isInitName(name string) bool {
	return name == "init" || strings.HasPrefix(name, "init#")
}

// variantID returns the driver ID for test-variant packages, or "" when
// the ID equals the import path.
func variantID(p *packages.Package) string {
	if p.ID != "" && p.ID != p.PkgPath {
		return p.ID
	}
	return ""
}

// importIDs maps each import path to the package Key it resolves to.
func importIDs(imports map[string]*packages.Package) map[string]string {
	if len(imports) == 0 {
		return nil
	}
	out := make(map[string]string, len(imports))
	for path, ip := range imports {
		if id := variantID(ip); id != "" {
			out[path] = id
		} else {
			out[path] = ip.PkgPath
		}
	}
	return out
}

func importPaths(imports map[string]*packages.Package) []string {
	paths := make([]string, 0, len(imports))
	for path := range imports {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	out := paths[:0]
	for i, p := range paths {
		if i == 0 || p != paths[i-1] {
			out = append(out, p)
		}
	}
	return out
}
