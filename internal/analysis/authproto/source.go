package authproto

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// This file adds the source-derived edge: fields that declare a
// `source` function binding get their freshness claim checked against
// the semantic program model. The check is deliberately narrow — it
// looks for calls into math/rand (predictable) versus crypto/rand
// (CSPRNG) inside the bound function and its bounded callee closure —
// and reports exactly what it saw. It never claims the bound function
// *is* the nonce generator beyond the declaration, and it never claims
// a CSPRNG call proves uniqueness.

// Evaluate runs the modeled checks (Analyze) and additionally
// verifies source-bound field claims against prog. prog may be nil,
// in which case Evaluate behaves exactly like Analyze and records a
// diagnostic noting that no source verification ran.
func Evaluate(ctx context.Context, prog *semantic.Program, contracts []*Contract, opts Options) (*Result, error) {
	opts = opts.withDefaults()
	res, err := Analyze(ctx, contracts, opts)
	if err != nil {
		return nil, err
	}
	if prog == nil {
		res.Diagnostics = append(res.Diagnostics, analysis.Diagnostic{
			Severity: analysis.DiagSeverityInfo,
			Category: analysis.DiagNote,
			Message:  "no semantic program supplied; source-bound field claims were not verified",
		})
		res.finish()
		return res, nil
	}
	prog.Index()
	res.Budgets = append(res.Budgets,
		analysis.Budget{Name: "max-source-depth", Limit: opts.MaxSourceDepth},
		analysis.Budget{Name: "max-source-functions", Limit: opts.MaxSourceFunctions},
	)
	for _, c := range contracts {
		if c == nil {
			continue
		}
		checkSourceBindings(c, prog, opts, res)
	}
	res.finish()
	return res, nil
}

// randKind classifies a call target's randomness source.
type randKind int

const (
	randNone randKind = iota
	randCrypto
	randMath
)

// checkSourceBindings verifies every fresh nonce/challenge field that
// declares a source function binding.
func checkSourceBindings(c *Contract, prog *semantic.Program, opts Options, res *Result) {
	for i := range c.Transcript {
		for j := range c.Transcript[i].Fields {
			f := &c.Transcript[i].Fields[j]
			if f.Source == nil {
				continue
			}
			if f.Kind != "nonce" && f.Kind != "challenge" {
				// Source bindings on other kinds are accepted but
				// only generation claims on freshness-bearing fields
				// are checked.
				res.Diagnostics = append(res.Diagnostics, analysis.Diagnostic{
					Severity: analysis.DiagSeverityInfo,
					Category: analysis.DiagNote,
					Message: fmt.Sprintf("contract %q: source binding on field %q (kind %q) is not a freshness claim; not verified",
						c.ID, f.Name, f.Kind),
				})
				continue
			}
			if !f.Fresh {
				continue // already flagged by the uniqueness check
			}
			checkNonceSource(c, prog, opts, res, f, i)
		}
	}
}

// checkNonceSource resolves the bound function and classifies its
// randomness usage.
func checkNonceSource(c *Contract, prog *semantic.Program, opts Options, res *Result, f *FieldSpec, stepIdx int) {
	spec := *f.Source
	matches, problem := resolveFunctions(prog, spec)
	switch {
	case problem != "":
		res.Diagnostics = append(res.Diagnostics, analysis.Diagnostic{
			Severity: analysis.DiagSeverityWarning,
			Category: analysis.DiagNote,
			Message: fmt.Sprintf("contract %q: field %q source binding is ambiguous (%s)",
				c.ID, f.Name, problem),
		})
		return
	case len(matches) == 0:
		res.Diagnostics = append(res.Diagnostics, analysis.Diagnostic{
			Severity: analysis.DiagSeverityWarning,
			Category: analysis.DiagNote,
			Message: fmt.Sprintf("contract %q: field %q source binding is unbound (%s); freshness remains a declared assumption",
				c.ID, f.Name, specSummary(spec)),
		})
		return
	}

	for _, fn := range matches {
		kind, pos := scanRandUsage(fn, opts)
		switch kind {
		case randMath:
			res.Findings = append(res.Findings, c.finding(c, "authproto.weak-randomness",
				"Nonce source reaches math/rand",
				fmt.Sprintf("%s field %q is declared fresh and bound to %s, which reaches math/rand at %s; math/rand output is predictable, so the uniqueness assumption does not hold in the modeled sense", f.Kind, f.Name, fn.ID, posString(pos)),
				analysis.StatusPotential, "medium",
				[]string{
					"the call-graph scan is bounded; rand usage through unbounded or unresolved call paths may be missed",
					"math/rand may still be seeded adequately for non-security uses, but it is not a CSPRNG",
				},
				append(traceSteps(c, stepIdx), analysis.EvidenceStep{
					Kind: analysis.EvidenceCall,
					Note: fmt.Sprintf("%s reaches math/rand at %s", fn.ID, posString(pos)),
					Span: spanFromPos(pos),
				}),
				map[string]string{
					"field":                 f.Name,
					"source_function":       fn.ID,
					"rand_source":           "math/rand",
					"attacker_capabilities": "attacker predicting nonce values and pre-computing/replaying proofs",
					"not_proven":            "that the function's output is used directly as the nonce, or that no other entropy is mixed in",
				},
				[]string{"use crypto/rand (or crypto/ecdh, crypto/elliptic nonce generation) for protocol nonces"}))
		case randCrypto:
			res.Diagnostics = append(res.Diagnostics, analysis.Diagnostic{
				Severity: analysis.DiagSeverityInfo,
				Category: analysis.DiagNote,
				Message: fmt.Sprintf("contract %q: field %q source %s reaches crypto/rand; CSPRNG use confirmed within scan bounds, uniqueness still assumed",
					c.ID, f.Name, fn.ID),
			})
		default:
			res.Diagnostics = append(res.Diagnostics, analysis.Diagnostic{
				Severity: analysis.DiagSeverityWarning,
				Category: analysis.DiagNote,
				Message: fmt.Sprintf("contract %q: field %q source %s shows no crypto/rand or math/rand call within scan bounds; freshness remains a declared assumption",
					c.ID, f.Name, fn.ID),
			})
		}
	}
}

// scanRandUsage performs a bounded breadth-first scan of fn's call
// graph looking for calls into math/rand or crypto/rand. It returns
// the strongest finding (math/rand wins — a may-analysis reports the
// worst case) and the source position of the first offending call.
func scanRandUsage(fn *semantic.Function, opts Options) (randKind, semantic.Position) {
	result := randNone
	var pos semantic.Position
	visited := map[string]bool{fn.ID: true}
	type item struct {
		fn    *semantic.Function
		depth int
	}
	queue := []item{{fn, 0}}
	visitedCount := 1
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		for _, call := range it.fn.Calls {
			k := classifyCall(call)
			if k == randNone {
				continue
			}
			if result == randNone || k == randMath {
				result = k
				if call.Site != nil {
					pos = call.Site.Position
				}
			}
		}
		if result == randMath {
			// math/rand dominates crypto/rand for reporting; no need to
			// explore further for a worse outcome.
			break
		}
		if opts.MaxSourceDepth >= 0 && it.depth >= opts.MaxSourceDepth {
			continue
		}
		if opts.MaxSourceFunctions >= 0 && visitedCount >= opts.MaxSourceFunctions {
			continue
		}
		for _, call := range it.fn.Calls {
			for _, callee := range call.Callees {
				if callee == nil || visited[callee.ID] || len(callee.Blocks) == 0 {
					continue
				}
				if callee.Package != nil && callee.Package.External {
					continue
				}
				visited[callee.ID] = true
				visitedCount++
				queue = append(queue, item{callee, it.depth + 1})
			}
		}
	}
	return result, pos
}

// classifyCall reports whether a call site targets math/rand or
// crypto/rand, checking both resolved callee package paths and the
// frontend's target description (which covers unresolved/external
// calls).
func classifyCall(call *semantic.Call) randKind {
	for _, callee := range call.Callees {
		if callee != nil && callee.Package != nil {
			switch {
			case callee.Package.Path == "math/rand" || strings.HasPrefix(callee.Package.Path, "math/rand/"):
				return randMath
			case callee.Package.Path == "crypto/rand":
				return randCrypto
			}
		}
	}
	t := call.Target
	switch {
	case strings.HasPrefix(t, "math/rand."):
		return randMath
	case strings.HasPrefix(t, "crypto/rand."):
		return randCrypto
	}
	return randNone
}

// resolveFunctions resolves a FunctionSpec against the program,
// mirroring the structural matching used by statemachine.Bind: exact
// ID, or name filtered by package path and receiver type. It returns
// sorted matches and a problem string for ambiguous specs.
func resolveFunctions(prog *semantic.Program, spec FunctionSpec) ([]*semantic.Function, string) {
	if spec.ID != "" {
		if fn := prog.Function(spec.ID); fn != nil {
			return []*semantic.Function{fn}, ""
		}
		return nil, ""
	}
	if spec.Name == "" {
		return nil, "function spec requires id or name"
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
		return nil, fmt.Sprintf("%d candidates (%s)", len(matches), strings.Join(ids, ", "))
	}
	return matches, ""
}

// receiverMatches reports whether the method receiver type matches the
// spec "[pkg/path.]Name". Pointer receivers are unwrapped.
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

// splitTypeSpec splits "[pkg/path.]Name" at the last dot.
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
	return t
}

// spanFromPos converts a semantic position to an analysis span.
func spanFromPos(p semantic.Position) analysis.Span {
	if !p.Valid() {
		return analysis.Span{}
	}
	return analysis.Span{
		File:        p.File,
		StartOffset: p.Offset,
		StartLine:   p.Line,
		StartColumn: p.Column,
		EndOffset:   p.EndOffset,
		EndLine:     p.EndLine,
		EndColumn:   p.EndColumn,
	}
}

// posString renders a position for messages.
func posString(p semantic.Position) string {
	if !p.Valid() {
		return "<unknown position>"
	}
	return fmt.Sprintf("%s:%d", p.File, p.Line)
}
