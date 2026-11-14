// Package pipeline integrates the semantic analysis engines
// (internal/analysis/*) into a single deterministic orchestration
// layer for the review CLI.
//
// The pipeline loads the Go semantic program model ONCE through
// internal/semantic/golang and shares the resulting *semantic.Program
// across every enabled analyzer — no analyzer repeats the expensive
// go/packages + SSA frontend work. Analyzers are registered
// declaratively with dependency ordering, executed with bounded
// parallelism under a shared semaphore, individually bounded by a
// timeout, isolated from each other's failures (panic/error/timeout
// become diagnostics, never run-aborting), and their results are
// merged in registration order so output is deterministic.
//
// All results are normalized into the shared analysis contract
// (internal/analysis): findings carry evidence traces, statuses, and
// truncation; load problems, unsupported constructs, and budget
// exhaustion surface as analysis.Diagnostics. Semantic analysis is
// opt-in: callers enable it explicitly and choose the analyzer set,
// contract directory, parallelism bound, timeouts, and budget depth.
package pipeline

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic/golang"
)

// Analyzer names recognized by Options.Analyzers and the CLI.
const (
	AnalyzerFlow         = "flow"
	AnalyzerStateMachine = "statemachine"
	AnalyzerTypeState    = "typestate"
	AnalyzerConcurrency  = "concurrency"
	AnalyzerAuthProto    = "authproto"
	AnalyzerProtocol     = "protocol"
)

// DefaultAnalyzers is the set enabled when Options.Analyzers is empty
// but semantic analysis itself was requested. Contract-driven
// analyzers report "skipped" when their contract family has no input.
var DefaultAnalyzers = []string{
	AnalyzerFlow,
	AnalyzerStateMachine,
	AnalyzerTypeState,
	AnalyzerConcurrency,
	AnalyzerAuthProto,
	AnalyzerProtocol,
}

// KnownAnalyzers lists every registered analyzer name, sorted.
func KnownAnalyzers() []string {
	return []string{
		AnalyzerAuthProto,
		AnalyzerConcurrency,
		AnalyzerFlow,
		AnalyzerProtocol,
		AnalyzerStateMachine,
		AnalyzerTypeState,
	}
}

// ValidAnalyzerName reports whether name is a registered analyzer.
func ValidAnalyzerName(name string) bool {
	for _, n := range KnownAnalyzers() {
		if n == name {
			return true
		}
	}
	return false
}

// Depth selects a budget preset applied to the engines' Options.
// "" and "standard" keep engine defaults; "deep" raises the bounded
// exploration/summary limits for more thorough (slower) analysis.
type Depth string

const (
	DepthStandard Depth = "standard"
	DepthDeep     Depth = "deep"
)

// Options controls one pipeline run. The zero value is not runnable:
// Dir must be set (the repository root containing the Go module).
type Options struct {
	// Dir is the directory passed to the Go frontend (repository
	// root). Required.
	Dir string
	// Pattern is the go/packages pattern selecting root packages.
	// Empty means "./...".
	Pattern string
	// Tests includes test variants of packages in the load.
	Tests bool
	// CallGraph selects call resolution. Zero value is
	// golang.CallGraphDefault (CHA).
	CallGraph golang.CallGraphMode
	// MaxPackages bounds modeled root packages (frontend default 256;
	// negative unlimited).
	MaxPackages int
	// MaxDiagnostics bounds recorded load diagnostics (frontend
	// default 2048; negative unlimited).
	MaxDiagnostics int

	// ContractDir is the directory scanned for statemachine/1,
	// typestate/1, authproto/1, and protocol/1 documents. Empty
	// defaults to <Dir>/.m3tal/contracts. A missing directory is not
	// an error: contract-driven analyzers report "skipped".
	ContractDir string

	// Analyzers selects the enabled analyzers by name. Empty means
	// DefaultAnalyzers. Unknown names are an error.
	Analyzers []string
	// MaxParallel bounds concurrent analyzer execution. Zero means
	// runtime.GOMAXPROCS(0); the bound is always at least 1.
	MaxParallel int
	// AnalyzerTimeout bounds each analyzer individually. Zero means
	// the default (10 minutes); negative means no per-analyzer timeout
	// (the caller's context still applies).
	AnalyzerTimeout time.Duration
	// LoadTimeout bounds the shared frontend load. Zero means the
	// default (15 minutes); negative means no timeout (the caller's
	// context still applies).
	LoadTimeout time.Duration
	// Depth selects engine budget presets. Empty means standard.
	Depth Depth

	// Loader optionally caches the loaded *semantic.Program across
	// runs (see Loader). Nil loads fresh each Run.
	Loader *Loader
}

const (
	defaultAnalyzerTimeout = 10 * time.Minute
	defaultLoadTimeout     = 15 * time.Minute
)

// ProgramInfo summarizes the loaded semantic program for reporting.
type ProgramInfo struct {
	Packages  int    `json:"packages"`
	Functions int    `json:"functions"`
	Values    int    `json:"values"`
	RootDir   string `json:"root_dir,omitempty"`
	Indexed   bool   `json:"indexed"`
}

// AnalyzerResult is the outcome of one analyzer.
type AnalyzerResult struct {
	// Name is the registered analyzer name.
	Name string `json:"name"`
	// Status is one of "completed", "skipped", "failed", "timeout".
	Status string `json:"status"`
	// Message is a short human-readable summary (counts, skip reason,
	// or failure detail).
	Message string `json:"message,omitempty"`
	// Findings are the analyzer's findings in the shared contract.
	Findings []analysis.Finding `json:"findings,omitempty"`
	// Diagnostics records analysis limitations specific to this
	// analyzer.
	Diagnostics []analysis.Diagnostic `json:"diagnostics,omitempty"`
	// Truncated is true when any engine budget was exhausted.
	Truncated bool `json:"truncated,omitempty"`
	// Assumptions lists caveats qualifying the analyzer's results.
	Assumptions []string `json:"assumptions,omitempty"`
}

// Result is the outcome of a pipeline run.
type Result struct {
	// Program describes the shared frontend load. Nil when the load
	// failed; LoadError then carries the reason.
	Program *ProgramInfo `json:"program,omitempty"`
	// LoadError is set when the semantic frontend could not produce a
	// program (e.g. no Go toolchain, unloadable module). It is a
	// diagnostic condition, not a run failure: analyzers are skipped
	// and the rest of the review proceeds.
	LoadError string `json:"load_error,omitempty"`
	// Analyzers has one entry per enabled analyzer, in deterministic
	// registration order regardless of execution scheduling.
	Analyzers []AnalyzerResult `json:"analyzers"`
	// Findings merges every analyzer's findings, deterministically
	// sorted with IDs assigned.
	Findings []analysis.Finding `json:"findings,omitempty"`
	// Diagnostics merges program-load and analyzer diagnostics,
	// deterministically sorted.
	Diagnostics []analysis.Diagnostic `json:"diagnostics,omitempty"`
	// Truncated is true when any analyzer or the frontend hit a bound.
	Truncated bool `json:"truncated,omitempty"`
}

// Run executes the semantic pipeline: it loads the program once,
// discovers contracts, runs the enabled analyzers with bounded
// parallelism, and merges results deterministically.
//
// A frontend load failure is reported through Result.LoadError and
// per-analyzer "skipped" statuses — Run only returns a non-nil error
// for invalid options.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if strings.TrimSpace(opts.Dir) == "" {
		return nil, fmt.Errorf("pipeline: Dir is required")
	}
	opts = opts.withDefaults()

	res := &Result{}

	// 1. Shared frontend load (cached when a Loader is configured).
	prog, err := loadProgram(ctx, opts)
	if err != nil {
		res.LoadError = err.Error()
		res.Diagnostics = append(res.Diagnostics, analysis.Diagnostic{
			Severity: analysis.DiagSeverityError,
			Category: analysis.DiagLoadError,
			Message:  "semantic frontend load failed: " + err.Error(),
		})
		// Still report every enabled analyzer as skipped so consumers
		// see the full intended run shape.
		for _, name := range enabledAnalyzers(opts) {
			res.Analyzers = append(res.Analyzers, AnalyzerResult{
				Name:    name,
				Status:  "skipped",
				Message: "semantic program unavailable",
			})
		}
		analysis.SortDiagnostics(res.Diagnostics)
		return res, nil
	}
	res.Program = programInfo(prog)
	for _, d := range prog.Diagnostics {
		res.Diagnostics = append(res.Diagnostics, diagnosticFromSemantic(d))
	}

	// 2. Contract discovery (failures are diagnostics, not errors).
	contracts, contractDiags := discoverContracts(opts.ContractDir)
	res.Diagnostics = append(res.Diagnostics, contractDiags...)

	env := &Env{Prog: prog, Contracts: contracts, Opts: opts}

	// 3. Bounded parallel analyzer execution.
	analyzers, err := selectAnalyzers(opts.Analyzers)
	if err != nil {
		return nil, err
	}
	ordered := orderAnalyzers(analyzers)
	results := runAnalyzers(ctx, ordered, env, opts)
	res.Analyzers = results

	// 4. Deterministic merge.
	var findings []analysis.Finding
	for _, r := range results {
		findings = append(findings, r.Findings...)
		res.Diagnostics = append(res.Diagnostics, r.Diagnostics...)
		for _, a := range r.Assumptions {
			res.Diagnostics = append(res.Diagnostics, analysis.Diagnostic{
				Severity: analysis.DiagSeverityInfo,
				Category: analysis.DiagNote,
				Message:  fmt.Sprintf("analyzer %q assumption: %s", r.Name, a),
			})
		}
		if r.Truncated {
			res.Truncated = true
		}
	}
	res.Findings = analysis.AssignFindingIDs(findings)
	analysis.SortFindings(res.Findings)
	analysis.SortDiagnostics(res.Diagnostics)
	return res, nil
}

func (o Options) withDefaults() Options {
	if o.Dir == "" {
		return o
	}
	if o.ContractDir == "" {
		o.ContractDir = defaultContractDir(o.Dir)
	}
	if o.AnalyzerTimeout == 0 {
		o.AnalyzerTimeout = defaultAnalyzerTimeout
	}
	if o.LoadTimeout == 0 {
		o.LoadTimeout = defaultLoadTimeout
	}
	if o.Depth == "" {
		o.Depth = DepthStandard
	}
	if o.MaxParallel <= 0 {
		o.MaxParallel = runtime.GOMAXPROCS(0)
	}
	if o.MaxParallel < 1 {
		o.MaxParallel = 1
	}
	return o
}

// defaultContractDir is the conventional per-repository contract
// directory.
func defaultContractDir(dir string) string {
	return filepath.Join(dir, ".m3tal", "contracts")
}

// enabledAnalyzers returns the analyzer names that will run, in
// registration order, without building engine state.
func enabledAnalyzers(opts Options) []string {
	defs := analyzerDefs()
	names := opts.Analyzers
	if len(names) == 0 {
		names = DefaultAnalyzers
	}
	byName := make(map[string]analyzerDef, len(defs))
	for _, d := range defs {
		byName[d.Name] = d
	}
	var out []string
	for _, n := range names {
		if _, ok := byName[n]; ok {
			out = append(out, n)
		}
	}
	return out
}

// selectAnalyzers validates the requested analyzer set and returns the
// corresponding definitions. Unknown names are an error; the returned
// slice preserves the caller's requested order (ordering for
// execution is applied separately by orderAnalyzers).
func selectAnalyzers(requested []string) ([]analyzerDef, error) {
	defs := analyzerDefs()
	byName := make(map[string]analyzerDef, len(defs))
	for _, d := range defs {
		byName[d.Name] = d
	}
	names := requested
	if len(names) == 0 {
		names = DefaultAnalyzers
	}
	var out []analyzerDef
	for _, n := range names {
		d, ok := byName[n]
		if !ok {
			return nil, fmt.Errorf("pipeline: unknown analyzer %q (valid: %s)", n, strings.Join(KnownAnalyzers(), ", "))
		}
		out = append(out, d)
	}
	return out, nil
}

// orderAnalyzers returns defs in dependency order (a topological sort
// over Analyzer.DependsOn). Ties keep registration order, so the
// schedule is deterministic. A dependency cycle cannot stall the run:
// remaining analyzers are emitted in registration order.
func orderAnalyzers(defs []analyzerDef) []analyzerDef {
	present := make(map[string]bool, len(defs))
	for _, d := range defs {
		present[d.Name] = true
	}
	// pendingDeps[name] = set of in-run dependencies not yet emitted.
	pendingDeps := make(map[string]map[string]bool, len(defs))
	for _, d := range defs {
		deps := make(map[string]bool)
		for _, dep := range d.DependsOn {
			if present[dep] {
				deps[dep] = true
			}
		}
		pendingDeps[d.Name] = deps
	}

	emitted := make(map[string]bool, len(defs))
	out := make([]analyzerDef, 0, len(defs))
	for len(out) < len(defs) {
		progress := false
		for _, d := range defs {
			if emitted[d.Name] {
				continue
			}
			ready := true
			for dep := range pendingDeps[d.Name] {
				if !emitted[dep] {
					ready = false
					break
				}
			}
			if !ready {
				continue
			}
			out = append(out, d)
			emitted[d.Name] = true
			progress = true
			break // restart scan: earlier defs may now be unblocked
		}
		if !progress {
			// Dependency cycle: emit the rest in registration order so
			// output stays deterministic and the run cannot deadlock.
			for _, d := range defs {
				if !emitted[d.Name] {
					out = append(out, d)
					emitted[d.Name] = true
				}
			}
		}
	}
	return out
}

// runAnalyzers executes defs with at most opts.MaxParallel running at
// once. Results are returned in defs order (which is the deterministic
// registration/dependency order), independent of completion order.
func runAnalyzers(ctx context.Context, defs []analyzerDef, env *Env, opts Options) []AnalyzerResult {
	results := make([]AnalyzerResult, len(defs))
	sem := make(chan struct{}, opts.MaxParallel)
	var wg sync.WaitGroup
	for i, def := range defs {
		wg.Add(1)
		go func(i int, def analyzerDef) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = runOne(ctx, def, env, opts)
		}(i, def)
	}
	wg.Wait()
	return results
}

// runOne executes a single analyzer with panic recovery, per-analyzer
// timeout, and context cancellation. Failures are converted into a
// "failed"/"timeout" result plus an error diagnostic — never propagated.
func runOne(ctx context.Context, def analyzerDef, env *Env, opts Options) (res AnalyzerResult) {
	res.Name = def.Name
	res.Status = "completed"

	actx := ctx
	cancel := func() {}
	if opts.AnalyzerTimeout > 0 {
		actx, cancel = context.WithTimeout(ctx, opts.AnalyzerTimeout)
	}
	defer cancel()

	outcome := make(chan analyzerOutcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				outcome <- analyzerOutcome{err: fmt.Errorf("panic: %v", r)}
			}
		}()
		outcome <- def.Run(actx, env)
	}()

	select {
	case oc := <-outcome:
		if oc.err != nil {
			res.Status = "failed"
			res.Message = oc.err.Error()
			res.Diagnostics = append(res.Diagnostics, analysis.Diagnostic{
				Severity: analysis.DiagSeverityError,
				Category: analysis.DiagNote,
				Message:  fmt.Sprintf("analyzer %q failed: %v", def.Name, oc.err),
			})
			return res
		}
		res.Findings = oc.Findings
		res.Diagnostics = oc.Diagnostics
		res.Truncated = oc.Truncated
		res.Assumptions = oc.Assumptions
		if oc.Skipped {
			res.Status = "skipped"
		}
		res.Message = outcomeMessage(oc)
		return res
	case <-actx.Done():
		if ctx.Err() != nil {
			// Caller cancelled the whole run.
			res.Status = "failed"
			res.Message = "canceled"
		} else {
			res.Status = "timeout"
			res.Message = fmt.Sprintf("exceeded analyzer timeout %s", opts.AnalyzerTimeout)
		}
		res.Diagnostics = append(res.Diagnostics, analysis.Diagnostic{
			Severity: analysis.DiagSeverityWarning,
			Category: analysis.DiagLimit,
			Message:  fmt.Sprintf("analyzer %q did not finish: %s", def.Name, res.Message),
		})
		return res
	}
}

// analyzerOutcome is what an analyzerDef.Run returns.
type analyzerOutcome struct {
	Findings    []analysis.Finding
	Diagnostics []analysis.Diagnostic
	Truncated   bool
	Assumptions []string
	Skipped     bool
	SkipReason  string
	err         error
}

func outcomeMessage(oc analyzerOutcome) string {
	if oc.Skipped {
		return oc.SkipReason
	}
	if len(oc.Findings) > 0 || len(oc.Diagnostics) > 0 {
		return fmt.Sprintf("%d findings, %d diagnostics", len(oc.Findings), len(oc.Diagnostics))
	}
	return "no findings"
}

// programInfo summarizes prog for reporting.
func programInfo(prog *semantic.Program) *ProgramInfo {
	if prog == nil {
		return nil
	}
	info := &ProgramInfo{RootDir: prog.RootDir}
	for _, pkg := range prog.Packages {
		info.Packages++
		info.Functions += len(pkg.Functions)
	}
	info.Values = len(prog.Values)
	return info
}

// diagnosticFromSemantic converts a semantic.Diagnostic into the
// shared analysis.Diagnostic contract.
func diagnosticFromSemantic(d semantic.Diagnostic) analysis.Diagnostic {
	out := analysis.Diagnostic{
		Severity: analysisDiagnosticSeverity(d.Severity),
		Category: analysis.DiagnosticCategory(d.Category),
		Message:  d.Message,
		Span:     spanFromPosition(d.Position),
	}
	if !out.Category.Valid() {
		out.Category = analysis.DiagNote
	}
	return out
}

func analysisDiagnosticSeverity(s semantic.Severity) analysis.DiagnosticSeverity {
	switch s {
	case semantic.SeverityError:
		return analysis.DiagSeverityError
	case semantic.SeverityWarning:
		return analysis.DiagSeverityWarning
	default:
		return analysis.DiagSeverityInfo
	}
}

// spanFromPosition maps a semantic.Position onto an analysis.Span.
func spanFromPosition(p semantic.Position) analysis.Span {
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
