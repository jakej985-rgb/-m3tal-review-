// Package flow implements interprocedural data-flow analysis over the
// engine-neutral semantic program model (internal/semantic).
//
// The analysis is deliberately language-neutral: it consumes only the
// semantic.Program model — stable value identities, explicit def-use
// relationships (Program.Uses), instruction operands/outputs, and
// CHA-resolved call may-sets (Call.Callees) — and never inspects
// frontend-specific IR.
//
// Two complementary results are produced:
//
//   - Per-function Summaries describing which parameters, globals,
//     fields/heap locations, and calls a function reads, writes, and
//     returns. Summaries are computed to a fixpoint so recursion and
//     mutual recursion converge (bounded by Options.MaxRounds).
//   - A value-flow query API (Analyzer.Flow / FlowResult.Trace) that
//     reconstructs interprocedural def-use chains through parameters,
//     arguments, returns, and call results for use as finding evidence.
//
// The analysis is a may-analysis: every fact is an over-approximation.
// Anything the model cannot resolve — dynamic calls with empty callee
// sets, external (bodiless) functions, unresolved operands, impure
// builtins — produces explicit "unknown" facts rather than silently
// safe assumptions.
package flow

import (
	"context"
	"sort"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// Options controls analysis budgets. All fields are optional; zero
// values select the defaults documented on each field.
type Options struct {
	// MaxRounds bounds the number of fixpoint iterations used to
	// converge interprocedural summaries. Recursive and mutually
	// recursive call cycles need several rounds; each round only
	// propagates facts one call edge further. Default 32.
	MaxRounds int
	// MaxFunctions bounds how many functions with bodies are
	// summarized, in deterministic function-ID order. Functions
	// beyond the bound are treated as unanalyzable callees (their
	// call sites are marked unknown). Default 2048; negative means
	// unlimited.
	MaxFunctions int
	// MaxOrigins bounds the number of distinct Origins tracked per
	// value dependence set, per place write set, and per summary
	// result. Exceeding the bound marks the owning function's
	// summary Truncated. Default 256; negative means unlimited.
	MaxOrigins int
	// MaxFlowEvents bounds the number of events a single Flow query
	// may visit before reporting Truncated. Default 8192;
	// negative means unlimited.
	MaxFlowEvents int
}

const (
	defaultMaxRounds     = 32
	defaultMaxFunctions  = 2048
	defaultMaxOrigins    = 256
	defaultMaxFlowEvents = 8192
)

func (o Options) withDefaults() Options {
	if o.MaxRounds <= 0 {
		o.MaxRounds = defaultMaxRounds
	}
	if o.MaxFunctions == 0 {
		o.MaxFunctions = defaultMaxFunctions
	}
	if o.MaxOrigins == 0 {
		o.MaxOrigins = defaultMaxOrigins
	}
	if o.MaxFlowEvents == 0 {
		o.MaxFlowEvents = defaultMaxFlowEvents
	}
	return o
}

// Analyzer runs data-flow analyses over a semantic.Program.
type Analyzer struct {
	prog *semantic.Program
	opts Options

	summaries  map[string]*Summary // by function ID
	analyzed   map[string]bool     // function IDs with a work item
	callers    map[string][]*callRef
	paramCache map[*semantic.Function][]*semantic.Value
	instrOwner map[*semantic.Instruction]*semantic.Function
	ownerIndex bool
}

// NewAnalyzer returns an Analyzer for prog. prog.Index must have been
// called by the frontend (golang.Load does this); NewAnalyzer calls it
// defensively so hand-built programs work too.
func NewAnalyzer(prog *semantic.Program, opts Options) *Analyzer {
	prog.Index()
	return &Analyzer{
		prog:      prog,
		opts:      opts.withDefaults(),
		summaries: make(map[string]*Summary),
		analyzed:  make(map[string]bool),
		callers:   make(map[string][]*callRef),
	}
}

// Result is the outcome of Analyze.
type Result struct {
	// Summaries maps function ID to its computed summary. Functions
	// without bodies (external stubs, ill-typed) have no entry.
	Summaries map[string]*Summary
	// Diagnostics records analysis limitations (budget exhaustion,
	// skipped functions).
	Diagnostics []semantic.Diagnostic
	// Truncated is true when the fixpoint budget was exhausted before
	// summaries converged; affected summaries carry Truncated=true.
	Truncated bool
}

// Summary returns the computed summary for a function ID, or nil.
func (a *Analyzer) Summary(fnID string) *Summary { return a.summaries[fnID] }

// Summaries returns all computed summaries keyed by function ID.
func (a *Analyzer) Summaries() map[string]*Summary { return a.summaries }

// Program returns the analyzed program.
func (a *Analyzer) Program() *semantic.Program { return a.prog }

// Analyze computes interprocedural summaries for every function with
// a body, iterating to a fixpoint bounded by Options.MaxRounds.
func (a *Analyzer) Analyze(ctx context.Context) *Result {
	res := &Result{Summaries: a.summaries}

	// Collect analyzable functions: modeled bodies only. External and
	// ill-typed packages carry no Blocks.
	var fns []*semantic.Function
	for _, pkg := range a.prog.Packages {
		for _, fn := range pkg.Functions {
			if len(fn.Blocks) == 0 {
				continue
			}
			fns = append(fns, fn)
		}
	}
	sort.Slice(fns, func(i, j int) bool { return fns[i].ID < fns[j].ID })
	if a.opts.MaxFunctions >= 0 && len(fns) > a.opts.MaxFunctions {
		fns = fns[:a.opts.MaxFunctions]
		res.Truncated = true
		res.Diagnostics = append(res.Diagnostics, semantic.Diagnostic{
			Severity: semantic.SeverityWarning,
			Category: semantic.DiagLimit,
			Message:  "function count exceeds MaxFunctions; remaining functions were not summarized",
		})
	}

	works := make([]*fnWork, 0, len(fns))
	for _, fn := range fns {
		w := newFnWork(a, fn)
		works = append(works, w)
		a.analyzed[fn.ID] = true
	}

	changed := make(map[string]bool, len(works))
	converged := false
	for round := 0; round < a.opts.MaxRounds && !converged; round++ {
		if err := ctx.Err(); err != nil {
			res.Diagnostics = append(res.Diagnostics, semantic.Diagnostic{
				Severity: semantic.SeverityWarning,
				Category: semantic.DiagLimit,
				Message:  "analysis canceled: " + err.Error(),
			})
			break
		}
		converged = true
		for _, w := range works {
			s := w.compute()
			prev := a.summaries[w.fn.ID]
			if prev == nil || !summaryEqual(prev, s) {
				converged = false
				changed[w.fn.ID] = true
			} else {
				delete(changed, w.fn.ID)
			}
			a.summaries[w.fn.ID] = s
		}
	}
	if !converged {
		res.Truncated = true
		res.Diagnostics = append(res.Diagnostics, semantic.Diagnostic{
			Severity: semantic.SeverityWarning,
			Category: semantic.DiagLimit,
			Message:  "summary fixpoint did not converge within MaxRounds; affected summaries are marked truncated",
		})
		// Only mark functions whose facts were still growing in the
		// final round.
		for id := range changed {
			if s := a.summaries[id]; s != nil && !s.Truncated {
				s.Truncated = true
				s.Reasons = appendUnique(s.Reasons, "fixpoint not reached within MaxRounds")
				sort.Strings(s.Reasons)
			}
		}
	}
	res.Diagnostics = append(res.Diagnostics, collectReasons(a.summaries)...)
	return res
}

// collectReasons surfaces per-function unknown/truncated reasons as
// program-level diagnostics so consumers see them without scanning
// every summary.
func collectReasons(summaries map[string]*Summary) []semantic.Diagnostic {
	var out []semantic.Diagnostic
	for _, s := range summaries {
		for _, r := range s.Reasons {
			out = append(out, semantic.Diagnostic{
				Severity: semantic.SeverityInfo,
				Category: semantic.DiagNote,
				Message:  s.Function.ID + ": " + r,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Message != out[j].Message {
			return out[i].Message < out[j].Message
		}
		return out[i].Category < out[j].Category
	})
	return out
}
