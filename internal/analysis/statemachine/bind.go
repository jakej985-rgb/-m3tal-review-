package statemachine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// This file binds contracts to program entities structurally through
// the semantic program model: exact function IDs, package paths,
// receiver types, declared types, and call relationships. Name
// matching is only ever a filtered candidate selector — zero matches
// is "unbound" and multiple matches is "ambiguous"; both are reported
// as diagnostics and never guessed.

// BoundContract is a contract resolved against a semantic.Program.
type BoundContract struct {
	// Contract is the parsed contract.
	Contract *Contract
	// Program is the program the contract was bound against.
	Program *semantic.Program
	// Diagnostics records binding problems: unbound functions/types,
	// ambiguous matches, invalid specs.
	Diagnostics []analysis.Diagnostic

	// data is the shared machine data for all instances of this
	// contract (unexported; see machine.go).
	data *boundContractData

	// Entries are the resolved exploration entry functions.
	Entries []*semantic.Function
	// EventFuncs maps a bound function ID to the sorted event names it
	// triggers. A function bound to multiple events forks the
	// exploration per event (may-analysis over ambiguous bindings).
	EventFuncs map[string][]string
	// Resource is the resolved subject type, or nil.
	Resource *semantic.Type
	// ResourceBound reports whether a declared resource type resolved.
	ResourceBound bool
	// SubjectArg maps event name → aligned argument index (-1 shared).
	SubjectArg map[string]int
	// HasSubjects reports whether any event resolves instances from
	// call arguments.
	HasSubjects bool
}

// ContractID returns the contract's ID.
func (bc *BoundContract) ContractID() string { return bc.Contract.ID }

// addDiag appends a binding diagnostic.
func (bc *BoundContract) addDiag(sev analysis.DiagnosticSeverity, msg string) {
	bc.Diagnostics = append(bc.Diagnostics, analysis.Diagnostic{
		Severity: sev,
		Category: analysis.DiagNote,
		Message:  fmt.Sprintf("contract %q: %s", bc.Contract.ID, msg),
	})
}

// Bind resolves c against prog and returns a BoundContract. Binding
// problems are reported through BoundContract.Diagnostics; a contract
// with fatal validation errors still binds what it can so evaluation
// can proceed on the valid subset.
func Bind(prog *semantic.Program, c *Contract) *BoundContract {
	bc := &BoundContract{
		Contract:   c,
		Program:    prog,
		EventFuncs: make(map[string][]string),
		SubjectArg: make(map[string]int),
	}
	_ = c.Check() // populate parsed expressions and indexes

	// Resolve the resource type.
	if c.Resource != nil && strings.TrimSpace(c.Resource.Type) != "" {
		bc.Resource = resolveType(prog, c.Resource.Type)
		if bc.Resource == nil {
			bc.addDiag(analysis.DiagSeverityWarning,
				fmt.Sprintf("resource type %q is unbound; instance tracking degrades to shared/unknown keys", c.Resource.Type))
		} else {
			bc.ResourceBound = true
		}
	}

	// Build shared machine data.
	data := &boundContractData{
		contract:           c,
		fieldInit:          make(map[string]Value),
		subjectArg:         make(map[string]int),
		transitionsByEvent: make(map[string][]int),
		maxField:           defaultMaxFieldValue,
	}
	initial := ""
	for _, s := range c.States {
		if s.Initial {
			initial = s.Name
		}
	}
	data.initial = initial
	for _, f := range c.Fields {
		data.fieldInit[f.Name] = fieldInitial(f)
	}
	for i, t := range c.Transitions {
		if c.invalidT[i] {
			continue
		}
		if _, ok := c.eventIndex[t.Event]; ok {
			data.transitionsByEvent[t.Event] = append(data.transitionsByEvent[t.Event], i)
		}
	}
	bc.data = data

	// Resolve events and their function bindings.
	for _, e := range c.Events {
		arg := 0
		if e.SubjectArg != nil {
			arg = *e.SubjectArg
		}
		bc.SubjectArg[e.Name] = arg
		data.subjectArg[e.Name] = arg
		if arg >= 0 {
			bc.HasSubjects = true
		}
		if e.Function == nil {
			continue
		}
		spec := *e.Function
		matches, problem := resolveFunctions(prog, spec, "event "+strconvQ(e.Name)+" function")
		switch {
		case problem != "":
			bc.addDiag(analysis.DiagSeverityWarning, problem)
		case len(matches) == 0:
			bc.addDiag(analysis.DiagSeverityWarning,
				fmt.Sprintf("event %q function binding is unbound (%s); the event never fires during program evaluation", e.Name, specSummary(spec)))
		default:
			for _, fn := range matches {
				bc.EventFuncs[fn.ID] = appendUniqueString(bc.EventFuncs[fn.ID], e.Name)
				// Validate subject_arg against the bound signature.
				if arg >= 0 && !argInRange(fn, arg) {
					bc.addDiag(analysis.DiagSeverityWarning,
						fmt.Sprintf("event %q subject_arg %d is out of range for %s", e.Name, arg, fn.ID))
				}
			}
		}
	}
	for id := range bc.EventFuncs {
		sort.Strings(bc.EventFuncs[id])
	}

	// Resolve entry points.
	if len(c.Entry) == 0 {
		for _, pkg := range prog.Packages {
			for _, fn := range pkg.Functions {
				if len(fn.Blocks) == 0 || fn.Synthetic {
					continue
				}
				bc.Entries = append(bc.Entries, fn)
			}
		}
	} else {
		for _, spec := range c.Entry {
			matches, problem := resolveFunctions(prog, spec, "entry point")
			switch {
			case problem != "":
				bc.addDiag(analysis.DiagSeverityWarning, problem)
			case len(matches) == 0:
				bc.addDiag(analysis.DiagSeverityWarning,
					fmt.Sprintf("entry point binding is unbound (%s)", specSummary(spec)))
			default:
				bc.Entries = append(bc.Entries, matches...)
			}
		}
	}
	// Dedupe and sort entries.
	seen := make(map[string]bool)
	var entries []*semantic.Function
	for _, fn := range bc.Entries {
		if fn == nil || seen[fn.ID] {
			continue
		}
		seen[fn.ID] = true
		entries = append(entries, fn)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	bc.Entries = entries

	sort.SliceStable(bc.Diagnostics, func(i, j int) bool {
		return bc.Diagnostics[i].Message < bc.Diagnostics[j].Message
	})
	return bc
}

// defaultMaxFieldValue is the fallback saturation bound for integer
// fields when Options.MaxFieldValue is not set.
const defaultMaxFieldValue = 4096

func fieldInitial(f FieldSpec) Value {
	switch strings.ToLower(f.Kind) {
	case "bool":
		if b, ok := f.Initial.(bool); ok {
			return Bool(b)
		}
		return Bool(false)
	default:
		switch v := f.Initial.(type) {
		case int:
			return Int(int64(v))
		case int64:
			return Int(v)
		case float64:
			return Int(int64(v))
		case string:
			if n, err := parseInt64(v); err == nil {
				return Int(n)
			}
		}
		return Int(0)
	}
}

func parseInt64(s string) (int64, error) {
	var n int64
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	return n, err
}

// argInRange reports whether index is a valid aligned argument index
// for fn (parameters including receiver).
func argInRange(fn *semantic.Function, idx int) bool {
	if fn.Signature == nil {
		return idx == 0 // unknown arity: only the receiver slot is safe
	}
	n := len(fn.Signature.Params)
	if fn.Signature.Recv != nil {
		n++
	}
	return idx >= 0 && idx < n
}

// resolveFunctions resolves a FunctionSpec against the program.
// It returns the sorted matches and a problem string for ambiguous
// matches ("" when the result is usable).
func resolveFunctions(prog *semantic.Program, spec FunctionSpec, what string) ([]*semantic.Function, string) {
	if spec.ID != "" {
		if fn := prog.Function(spec.ID); fn != nil {
			return []*semantic.Function{fn}, ""
		}
		return nil, ""
	}
	if spec.Name == "" {
		return nil, what + ": function spec requires id or name"
	}
	var matches []*semantic.Function
	for _, pkg := range prog.Packages {
		for _, fn := range pkg.Functions {
			if fn.Name != spec.Name {
				continue
			}
			if spec.Package != "" && pkg.Path != spec.Package {
				continue
			}
			if spec.Receiver != "" && !receiverMatches(fn.Receiver, spec.Receiver) {
				continue
			}
			matches = append(matches, fn)
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].ID < matches[j].ID })
	if len(matches) > 1 {
		ids := make([]string, 0, len(matches))
		for _, fn := range matches {
			ids = append(ids, fn.ID)
		}
		if len(ids) > 8 {
			ids = append(ids[:8], fmt.Sprintf("... and %d more", len(matches)-8))
		}
		return nil, fmt.Sprintf("%s binding for %q is ambiguous: %d candidates (%s)",
			what, spec.Name, len(matches), strings.Join(ids, ", "))
	}
	return matches, ""
}

// receiverMatches reports whether the method receiver type matches the
// spec "[pkg/path.]Name". Pointer receivers are unwrapped on both
// sides.
func receiverMatches(recv *semantic.Type, spec string) bool {
	if recv == nil {
		return false
	}
	wantPkg, wantName := splitTypeSpec(spec)
	base := unwrapType(recv)
	if base == nil || base.Kind != semantic.TypeNamed && base.Kind != semantic.TypeAlias {
		return false
	}
	if wantName != "" && base.Name != wantName {
		return false
	}
	if wantPkg != "" && base.Package != wantPkg {
		return false
	}
	return true
}

// resolveType resolves a "[pkg/path][*].Name" type spec against the
// program's declared types.
func resolveType(prog *semantic.Program, spec string) *semantic.Type {
	spec = strings.TrimPrefix(strings.TrimSpace(spec), "*")
	pkgPath, name := splitTypeSpec(spec)
	if name == "" {
		return nil
	}
	var matches []*semantic.Type
	for _, pkg := range prog.Packages {
		if pkgPath != "" && pkg.Path != pkgPath {
			continue
		}
		for _, t := range pkg.Types {
			if t.Name == name {
				matches = append(matches, t)
			}
		}
	}
	if len(matches) != 1 {
		return nil // unbound or ambiguous: reported by caller
	}
	return matches[0]
}

// splitTypeSpec splits "[pkg/path.]Name" at the last dot. Import paths
// contain dots and slashes, but type names never contain dots, so the
// last dot is always the package/name separator.
func splitTypeSpec(spec string) (pkg, name string) {
	spec = strings.TrimPrefix(strings.TrimSpace(spec), "*")
	if i := strings.LastIndex(spec, "."); i >= 0 {
		return spec[:i], spec[i+1:]
	}
	return "", spec
}

// unwrapType follows pointer (and alias) wrappers to the base named
// type.
func unwrapType(t *semantic.Type) *semantic.Type {
	for t != nil {
		switch t.Kind {
		case semantic.TypePointer:
			t = t.Elem
		case semantic.TypeAlias:
			t = t.Aliasee
		default:
			return t
		}
	}
	return nil
}

func appendUniqueString(xs []string, x string) []string {
	for _, e := range xs {
		if e == x {
			return xs
		}
	}
	return append(xs, x)
}

func strconvQ(s string) string { return fmt.Sprintf("%q", s) }

func specSummary(spec FunctionSpec) string {
	if spec.ID != "" {
		return "id=" + spec.ID
	}
	var parts []string
	if spec.Name != "" {
		parts = append(parts, "name="+spec.Name)
	}
	if spec.Package != "" {
		parts = append(parts, "package="+spec.Package)
	}
	if spec.Receiver != "" {
		parts = append(parts, "receiver="+spec.Receiver)
	}
	return strings.Join(parts, ", ")
}
