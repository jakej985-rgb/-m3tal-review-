// Package semantic defines an engine-neutral program model: a typed,
// navigable representation of a codebase that downstream analyzers can
// query without depending on any language-specific frontend.
//
// The model is deliberately structural rather than diagnostic: it
// describes what the program *is* (packages, functions, control-flow
// blocks, instructions, calls, types, source positions) and leaves all
// security or behavioral reasoning to consumers. Frontends populate the
// model from language toolchains; see internal/semantic/golang for the
// Go implementation.
//
// All collections in a Program are deterministically ordered so that
// two loads of the same repository state produce identical models.
package semantic

import "sort"

// Program is the root of a loaded codebase.
type Program struct {
	// RootDir is the absolute directory the program was loaded from.
	RootDir string

	// Packages contains every modeled package, sorted by Path, with
	// test variants sharing a Path ordered by Key(). This
	// includes analyzed (root) packages and stub packages materialized
	// for external callees referenced by call sites.
	Packages []*Package

	// Values contains every modeled value — function-scoped values
	// (parameters, instruction results, constants) and shared values
	// (globals, function references, builtins) — sorted by ID.
	Values []*Value

	// Diagnostics records load failures, type errors, unsupported
	// constructs, and other analysis limitations. Nothing is silently
	// skipped: problems surface here.
	Diagnostics []Diagnostic

	byKey      map[string]*Package
	byFuncID   map[string]*Function
	byValueID  map[string]*Value
	uses       map[*Value][]*Instruction
	callBySite map[*Instruction]*Call
}

// Package returns the package with the given ID (the import path for
// ordinary packages, or e.g. "x [x.test]" for test variants), or nil.
func (p *Program) Package(key string) *Package { return p.byKey[key] }

// Function returns the function with the given stable ID, or nil.
func (p *Program) Function(id string) *Function { return p.byFuncID[id] }

// Value returns the value with the given stable ID, or nil.
func (p *Program) Value(id string) *Value { return p.byValueID[id] }

// Uses returns the instructions that consume v as an operand, in
// deterministic traversal order. The slice is empty for values with no
// modeled uses (e.g. dead definitions or unresolved operands).
func (p *Program) Uses(v *Value) []*Instruction { return p.uses[v] }

// Index builds the lookup maps used by Package, Function, and CallAt.
// Frontends call it once after the package graph is fully
// materialized.
func (p *Program) Index() {
	p.byKey = make(map[string]*Package, len(p.Packages))
	p.byFuncID = make(map[string]*Function)
	p.byValueID = make(map[string]*Value, len(p.Values))
	p.uses = make(map[*Value][]*Instruction)
	p.callBySite = make(map[*Instruction]*Call)
	for _, v := range p.Values {
		p.byValueID[v.ID] = v
	}
	seenUse := make(map[*Value]map[*Instruction]bool)
	for _, pkg := range p.Packages {
		p.byKey[pkg.Key()] = pkg
		for _, fn := range pkg.Functions {
			if _, dup := p.byFuncID[fn.ID]; !dup {
				p.byFuncID[fn.ID] = fn
			}
		}
		for _, fn := range pkg.Functions {
			for _, c := range fn.Calls {
				p.callBySite[c.Site] = c
			}
			for _, b := range fn.Blocks {
				for _, instr := range b.Instructions {
					for _, operand := range instr.Operands {
						if operand == nil {
							continue
						}
						m := seenUse[operand]
						if m == nil {
							m = make(map[*Instruction]bool)
							seenUse[operand] = m
						}
						if !m[instr] {
							m[instr] = true
							p.uses[operand] = append(p.uses[operand], instr)
						}
					}
				}
			}
		}
	}
}

// CallAt returns the Call whose site is the given instruction, or nil.
func (p *Program) CallAt(site *Instruction) *Call { return p.callBySite[site] }

// Sort orders every collection in the program deterministically.
func (p *Program) Sort() {
	sort.Slice(p.Packages, func(i, j int) bool {
		a, b := p.Packages[i], p.Packages[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Key() < b.Key()
	})
	sort.Slice(p.Values, func(i, j int) bool { return p.Values[i].ID < p.Values[j].ID })
	for _, pkg := range p.Packages {
		pkg.Sort()
	}
	sort.Slice(p.Diagnostics, func(i, j int) bool {
		a, b := p.Diagnostics[i], p.Diagnostics[j]
		if a.Position.File != b.Position.File {
			return a.Position.File < b.Position.File
		}
		if a.Position.Offset != b.Position.Offset {
			return a.Position.Offset < b.Position.Offset
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.Message < b.Message
	})
}

// Key returns the package's unique identity: ID when set, else Path.
func (p *Package) Key() string {
	if p.ID != "" {
		return p.ID
	}
	return p.Path
}

// Package is a single importable package.
type Package struct {
	// Path is the package's import path (e.g. "github.com/x/y/sub").
	// Test variants share Path with the ordinary package.
	Path string
	// ID uniquely identifies the package variant within the program
	// (e.g. "x [x.test]" for a test variant). Empty means Path.
	ID string
	// Name is the package clause name (e.g. "sub").
	Name string

	// Files are the source files that comprise the package.
	Files []*File
	// Functions are the modeled functions, sorted by ID.
	Functions []*Function
	// Types are the declared (non-builtin) types, sorted by Name.
	Types []*Type
	// Imports lists the import paths this package depends on,
	// sorted and deduplicated.
	Imports []string
	// ImportIDs maps each import path to the package ID it resolves to
	// in this build (differs from the path for test variants). Use
	// Program.Package(ImportIDs[path]) to find the imported variant.
	ImportIDs map[string]string

	// IsCommand is true for package main.
	IsCommand bool
	// IllTyped is true when the package has type errors; its function
	// bodies may be missing or partial.
	IllTyped bool
	// External is true for stub packages materialized only because an
	// analyzed package references their members (e.g. standard library
	// or third-party dependencies that were not part of the load set).
	// External packages carry signatures but no bodies.
	External bool
	// IgnoredFiles lists source files excluded by build constraints.
	IgnoredFiles []string
	// TypesInfo is the frontend's raw type-checker info for the package,
	// retained for consumers that need it. Engine-agnostic code must not
	// depend on its concrete type.
	TypesInfo any
}

// Sort orders the package's collections deterministically.
func (p *Package) Sort() {
	sort.Slice(p.Files, func(i, j int) bool { return p.Files[i].Path < p.Files[j].Path })
	sort.Slice(p.Functions, func(i, j int) bool { return p.Functions[i].ID < p.Functions[j].ID })
	sort.Slice(p.Types, func(i, j int) bool { return p.Types[i].Name < p.Types[j].Name })
	sort.Strings(p.Imports)
}

// File is a single source file.
type File struct {
	// Path is the file's path as reported by the frontend (typically
	// absolute).
	Path string
	// Package is the owning package.
	Package *Package
	// AST retains the frontend's parsed syntax tree for the file.
	// Engine-agnostic code must not depend on its concrete type.
	AST any
}

// Function is a callable unit: a declared function, method, initializer,
// or closure.
type Function struct {
	// ID is a stable, package-qualified identifier, unique within the
	// program. It is the canonical way to refer to a function.
	ID string
	// Name is the function's short name (e.g. "ServeHTTP", "init",
	// "main$1" for closures).
	Name string
	// Package is the package the function belongs to.
	Package *Package

	// Kind classifies the function.
	Kind FuncKind
	// Signature describes parameters, results, and receiver.
	Signature *Signature
	// Receiver is the method receiver type, or nil for package-level
	// functions. It duplicates Signature.Recv for convenience.
	Receiver *Type

	// Blocks are the function's basic blocks in layout order.
	// External and ill-typed functions may have none.
	Blocks []*BasicBlock
	// Calls are the call sites within this function, in instruction
	// order.
	Calls []*Call
	// Values are the function-scoped values in deterministic creation
	// order: parameters and free variables first, then instruction
	// results and constants in order of first encounter.
	Values []*Value

	// Exported reports whether the function is exported.
	Exported bool
	// Synthetic reports whether the function was generated by the
	// frontend (wrappers, thunks, generic instances, init stubs)
	// rather than written literally in source.
	Synthetic bool
	// Position is the function's declaration site. The zero value
	// means no source position is available.
	Position Position
}

// FuncKind classifies a Function.
type FuncKind int

const (
	// FuncDecl is a declared package-level function.
	FuncDecl FuncKind = iota
	// FuncMethod is a declared method with a receiver.
	FuncMethod
	// FuncInit is an init function or the synthesized package
	// initializer.
	FuncInit
	// FuncClosure is an anonymous function literal.
	FuncClosure
	// FuncSynthetic is a compiler- or frontend-generated function
	// (wrappers, thunks, bound methods, generic instances).
	FuncSynthetic
)

// BasicBlock is a maximal sequence of instructions with a single entry
// and single exit.
type BasicBlock struct {
	// ID is unique within the function.
	ID int
	// Index is the block's position in the function's Blocks slice.
	Index int
	// Instructions are the block's instructions in execution order.
	Instructions []*Instruction
	// Successors are the blocks control may flow to next.
	Successors []*BasicBlock
	// Predecessors are the blocks that may flow into this one.
	Predecessors []*BasicBlock
}

// Instruction is a single semantic operation within a basic block.
type Instruction struct {
	// ID is unique within the function.
	ID int
	// Op is the neutral operation category.
	Op Op
	// Operands are the instruction's input values. Every operand is a
	// shared *Value whose ID, definition, and uses can be traversed;
	// operands that cannot be modeled use Kind==ValueUnresolved.
	Operands []*Value
	// Outputs are the values this instruction defines. Most
	// value-producing instructions define exactly one; instructions
	// with no result (stores, jumps, returns) define none.
	Outputs []*Value
	// Detail carries opcode-specific text (e.g. the concrete SSA
	// instruction name for OpOther, a constant rendering for OpConst).
	Detail string
	// Position is the instruction's source position.
	Position Position
}

// Op is a language-neutral instruction category. Frontends map their
// IR onto these categories; OpOther covers anything without a dedicated
// category (see Instruction.Detail for the frontend-specific name).
type Op int

const (
	OpInvalid Op = iota
	// OpConst is a constant or literal materialization.
	OpConst
	// OpAlloc is an allocation (new, make, composite literal).
	OpAlloc
	// OpLoad reads through a pointer or memory location.
	OpLoad
	// OpStore writes through a pointer or memory location.
	OpStore
	// OpAddr computes an address (address-of).
	OpAddr
	// OpField accesses a struct field.
	OpField
	// OpIndex indexes a slice, array, string, or map.
	OpIndex
	// OpSlice extracts a subslice or substring.
	OpSlice
	// OpCall is a function or method call.
	OpCall
	// OpGo starts a goroutine.
	OpGo
	// OpDefer schedules a deferred call.
	OpDefer
	// OpReturn returns from the function.
	OpReturn
	// OpBranch is a conditional control transfer.
	OpBranch
	// OpJump is an unconditional control transfer.
	OpJump
	// OpPhi merges values from predecessor blocks.
	OpPhi
	// OpConvert changes a value's type without changing its
	// representation semantics (conversions, interface boxing).
	OpConvert
	// OpTypeAssert extracts a concrete type from an interface.
	OpTypeAssert
	// OpSend sends on a channel.
	OpSend
	// OpRecv receives from a channel.
	OpRecv
	// OpOther is anything not covered above.
	OpOther
)

// ValueKind identifies where a Value comes from.
type ValueKind int

const (
	// ValueInstr is defined by an instruction's Outputs.
	ValueInstr ValueKind = iota
	// ValueParam is a function parameter (including the receiver).
	ValueParam
	// ValueFreeVar is a variable captured from an enclosing function.
	ValueFreeVar
	// ValueGlobal is a package-level variable.
	ValueGlobal
	// ValueConst is a compile-time constant.
	ValueConst
	// ValueFunction is a reference to a function (e.g. a call target
	// operand); Func links to the modeled function when available.
	ValueFunction
	// ValueBuiltin is a reference to a language builtin (panic, append,
	// len, ...).
	ValueBuiltin
	// ValueUnresolved marks an operand the frontend could not model.
	// Unresolved values still carry a best-effort Name and Type so
	// consumers can display them, but they have no Def and participate
	// in no def/use chains.
	ValueUnresolved
)

// Value is a stable semantic identity for a program value. IDs are
// unique across the Program: function-scoped values use the form
// "<function ID>@<n>" ("@" never appears in frontend function names)
// while shared values use their natural identity (function ID for
// ValueFunction, "global:<pkg path>.<name>" for ValueGlobal,
// "builtin:<name>" for ValueBuiltin).
type Value struct {
	// ID is the stable, program-unique identifier.
	ID string
	// Name is the frontend's display name, if any. Names are NOT
	// identities: they may be empty, reused across scopes, or shared
	// by distinct values.
	Name string
	// Type is the value's type, if known.
	Type *Type
	// Kind identifies the value's origin.
	Kind ValueKind
	// Def is the instruction that defines this value, for
	// Kind==ValueInstr. It is nil for parameters, free variables,
	// globals, constants, function references, builtins, and
	// unresolved values.
	Def *Instruction
	// Owner is the function that scopes this value, for function-
	// scoped kinds. It is nil for shared values.
	Owner *Function
	// Package is the owning package for ValueGlobal values.
	Package *Package
	// Func links to the modeled function for Kind==ValueFunction when
	// the callee could be materialized; nil otherwise.
	Func *Function
	// Position is the value's source position where available (e.g.
	// parameter declarations, global declarations).
	Position Position
}

// CallKind classifies a call site.
type CallKind int

const (
	// CallDirect is an ordinary synchronous call.
	CallDirect CallKind = iota
	// CallGo is a "go f()" invocation.
	CallGo
	// CallDefer is a "defer f()" invocation.
	CallDefer
	// CallRunDefers is an implicit deferred-call flush.
	CallRunDefers
)

// Call is a call site within a function.
type Call struct {
	// Site is the instruction that performs the call.
	Site *Instruction
	// Kind is the call flavor (direct, go, defer, run-defers).
	Kind CallKind
	// Target is a human-readable description of the callee
	// expression, resolved when possible (e.g. "net/http.(*Client).Get",
	// or a description of a dynamic call target).
	Target string
	// Callees are the functions this site may invoke, sorted by ID
	// and deduplicated. For direct calls this is the single resolved
	// function; for dynamic calls it is the may-set computed by the
	// frontend's call-resolution strategy (which may be empty when
	// resolution is disabled or impossible).
	Callees []*Function
	// Dynamic reports whether the callee could not be resolved
	// statically and required call-graph analysis (or remained
	// unresolved).
	Dynamic bool
}

// Signature describes a function type.
type Signature struct {
	// Params are the parameter types, in order.
	Params []*Type
	// Results are the result types, in order.
	Results []*Type
	// Recv is the receiver type for methods, nil otherwise.
	Recv *Type
	// Variadic reports whether the last parameter is variadic.
	Variadic bool
	// TypeParams are the names of declared type parameters, if any.
	TypeParams []string
}

// TypeKind classifies a Type.
type TypeKind int

const (
	TypeInvalid TypeKind = iota
	// TypeBasic is a predeclared type (int, string, bool, error, any...).
	TypeBasic
	// TypeNamed is a defined (named) type, possibly generic.
	TypeNamed
	// TypePointer is a pointer type.
	TypePointer
	// TypeSlice is a slice type.
	TypeSlice
	// TypeArray is an array type.
	TypeArray
	// TypeMap is a map type.
	TypeMap
	// TypeChan is a channel type.
	TypeChan
	// TypeFunc is a function type.
	TypeFunc
	// TypeStruct is an anonymous struct type.
	TypeStruct
	// TypeInterface is an anonymous interface type.
	TypeInterface
	// TypeTuple is a parenthesized multi-value type.
	TypeTuple
	// TypeTypeParam is a type parameter.
	TypeTypeParam
	// TypeAlias is a declared type alias (e.g. "type A = B"). The
	// alias keeps its own name and package identity; the type it
	// denotes is reachable via Aliasee.
	TypeAlias
)

// Type is a semantic type description. Text always carries the
// frontend's canonical rendering (e.g. types.Type.String() for Go) so
// consumers can display or match on it even when structured fields are
// not populated.
type Type struct {
	Kind TypeKind
	// Text is the canonical string rendering of the type.
	Text string
	// Name is the short name for TypeBasic, TypeNamed, TypeAlias, and
	// TypeTypeParam.
	Name string
	// Package is the import path that defines a TypeNamed or TypeAlias.
	Package string
	// Elem is the element type for pointer, slice, array, and channel
	// types.
	Elem *Type
	// Key is the key type for map types.
	Key *Type
	// ArrayLen is the element count for array types, or -1 if unknown.
	ArrayLen int64
	// Signature is populated for TypeFunc.
	Signature *Signature
	// TypeArgs are the type arguments for an instantiated generic type
	// or generic alias.
	TypeArgs []*Type
	// Aliasee is the immediate right-hand side of a declared alias;
	// it is populated only when Kind == TypeAlias. For alias chains
	// ("type A = B; type B = string") Aliasee is itself a TypeAlias,
	// so every link of the chain keeps its own identity. Text renders
	// the alias name, not its expansion; consumers that need the
	// fully-expanded type should use Unaliased.
	Aliasee *Type
	// IsAlias reports whether the type denotes a declared type alias.
	// It is true exactly when Kind == TypeAlias.
	IsAlias bool
}

// Unaliased follows Aliasee links and returns the first non-alias type.
// It returns t unchanged when t is not an alias.
func (t *Type) Unaliased() *Type {
	for t != nil && t.Kind == TypeAlias && t.Aliasee != nil {
		t = t.Aliasee
	}
	return t
}

// Position identifies a source range. Line and Column are 1-based;
// Offset is 0-based. A zero Position means "no source position".
type Position struct {
	File      string
	Offset    int
	Line      int
	Column    int
	EndOffset int
	EndLine   int
	EndColumn int
}

// Valid reports whether the position carries usable source information.
func (p Position) Valid() bool { return p.File != "" }
