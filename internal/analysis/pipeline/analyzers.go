package pipeline

import (
	"context"
	"fmt"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"github.com/jakej985-rgb/m3tal-review/internal/analysis/authproto"
	"github.com/jakej985-rgb/m3tal-review/internal/analysis/concurrency"
	"github.com/jakej985-rgb/m3tal-review/internal/analysis/flow"
	"github.com/jakej985-rgb/m3tal-review/internal/analysis/protocol"
	"github.com/jakej985-rgb/m3tal-review/internal/analysis/statemachine"
	"github.com/jakej985-rgb/m3tal-review/internal/analysis/typestate"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// Env is the shared analysis context handed to every analyzer: the
// one loaded *semantic.Program plus the discovered contract sets.
type Env struct {
	Prog      *semantic.Program
	Contracts *Contracts
	Opts      Options
}

// analyzerDef declares one registered analyzer. DependsOn lists
// analyzer names that must be ordered before this one; the current
// engines are independent (each builds on the shared program and, for
// contract-driven analyzers, on the shared contract sets), but the
// ordering mechanism is in place for engines with real dependencies.
type analyzerDef struct {
	Name      string
	DependsOn []string
	Run       func(ctx context.Context, env *Env) analyzerOutcome
}

// analyzerDefs returns the full registry in canonical registration
// order. This order also defines result ordering for analyzers with
// equal dependency depth.
func analyzerDefs() []analyzerDef {
	return []analyzerDef{
		{Name: AnalyzerFlow, Run: runFlow},
		{Name: AnalyzerStateMachine, Run: runStateMachine},
		{Name: AnalyzerTypeState, Run: runTypeState},
		{Name: AnalyzerConcurrency, Run: runConcurrency},
		{Name: AnalyzerAuthProto, Run: runAuthProto},
		{Name: AnalyzerProtocol, Run: runProtocol},
	}
}

// --- flow -----------------------------------------------------------

func runFlow(ctx context.Context, env *Env) analyzerOutcome {
	res := flow.NewAnalyzer(env.Prog, env.Opts.flowOptions()).Analyze(ctx)
	out := analyzerOutcome{Truncated: res.Truncated}
	for _, d := range res.Diagnostics {
		out.Diagnostics = append(out.Diagnostics, diagnosticFromSemantic(d))
	}
	return out
}

// --- statemachine ---------------------------------------------------

func runStateMachine(ctx context.Context, env *Env) analyzerOutcome {
	contracts := env.Contracts.StateMachine
	if len(contracts) == 0 {
		return analyzerOutcome{Skipped: true, SkipReason: "no statemachine/1 contracts found"}
	}
	res, err := statemachine.Evaluate(ctx, env.Prog, contracts, env.Opts.stateMachineOptions())
	if err != nil {
		return analyzerOutcome{err: err}
	}
	return stateMachineOutcome(res)
}

func stateMachineOutcome(res *statemachine.Result) analyzerOutcome {
	if res == nil {
		return analyzerOutcome{err: fmt.Errorf("analyzer returned no result")}
	}
	out := analyzerOutcome{
		Findings:    res.Findings,
		Diagnostics: res.Diagnostics,
		Truncated:   res.Truncated,
		Assumptions: res.Assumptions,
	}
	for _, b := range res.Budgets {
		if b.Truncated {
			out.Diagnostics = append(out.Diagnostics, analysis.Diagnostic{
				Severity: analysis.DiagSeverityWarning,
				Category: analysis.DiagLimit,
				Message:  fmt.Sprintf("analysis budget %q was exhausted", b.Name),
			})
		}
	}
	return out
}

// --- typestate ------------------------------------------------------

func runTypeState(ctx context.Context, env *Env) analyzerOutcome {
	specs := env.Contracts.TypeState
	if len(specs) == 0 {
		return analyzerOutcome{Skipped: true, SkipReason: "no typestate/1 specs found"}
	}
	res, err := typestate.Analyze(ctx, env.Prog, specs, env.Opts.stateMachineOptions())
	if err != nil {
		return analyzerOutcome{err: err}
	}
	return stateMachineOutcome(res)
}

// --- concurrency ----------------------------------------------------

func runConcurrency(ctx context.Context, env *Env) analyzerOutcome {
	res := concurrency.NewAnalyzer(env.Prog, env.Opts.concurrencyOptions()).Analyze(ctx)
	return analyzerOutcome{
		Findings:    res.Findings,
		Diagnostics: res.Diagnostics,
		Truncated:   res.Truncated,
	}
}

// --- authproto ------------------------------------------------------

func runAuthProto(ctx context.Context, env *Env) analyzerOutcome {
	contracts := env.Contracts.AuthProto
	if len(contracts) == 0 {
		return analyzerOutcome{Skipped: true, SkipReason: "no authproto/1 contracts found"}
	}
	res, err := authproto.Evaluate(ctx, env.Prog, contracts, env.Opts.authProtoOptions())
	if err != nil {
		return analyzerOutcome{err: err}
	}
	if res == nil {
		return analyzerOutcome{err: fmt.Errorf("analyzer returned no result")}
	}
	out := analyzerOutcome{
		Findings:    res.Findings,
		Diagnostics: res.Diagnostics,
		Truncated:   res.Truncated,
		Assumptions: res.Assumptions,
	}
	for _, b := range res.Budgets {
		if b.Truncated {
			out.Diagnostics = append(out.Diagnostics, analysis.Diagnostic{
				Severity: analysis.DiagSeverityWarning,
				Category: analysis.DiagLimit,
				Message:  fmt.Sprintf("analysis budget %q was exhausted", b.Name),
			})
		}
	}
	return out
}

// --- protocol -------------------------------------------------------

func runProtocol(_ context.Context, env *Env) analyzerOutcome {
	set := env.Contracts.Protocol
	versions := env.Contracts.ProtocolVersions
	if set == nil || len(versions) < 2 {
		return analyzerOutcome{Skipped: true, SkipReason: "fewer than two protocol/1 snapshots found"}
	}
	// The snapshot set's versions are the deployed-version labels the
	// checkout knows about; EvaluateMatrix compares every unordered
	// pair in both directions.
	res := protocol.EvaluateMatrix(set, versions)
	out := analyzerOutcome{
		Findings:    res.Findings,
		Diagnostics: res.Diagnostics,
	}
	// Cells with Missing snapshots or unsuppressed breaking findings
	// qualify completeness.
	for _, row := range res.Cells {
		for _, cell := range row {
			if cell.Missing {
				out.Truncated = true
			}
		}
	}
	return out
}

// --- budget depth presets -------------------------------------------

func (o Options) flowOptions() flow.Options {
	if o.Depth != DepthDeep {
		return flow.Options{}
	}
	return flow.Options{
		MaxRounds:     48,
		MaxFunctions:  4096,
		MaxOrigins:    512,
		MaxFlowEvents: 16384,
	}
}

func (o Options) stateMachineOptions() statemachine.Options {
	if o.Depth != DepthDeep {
		return statemachine.Options{}
	}
	return statemachine.Options{
		FlowOptions:  o.flowOptions(),
		MaxSteps:     200000,
		MaxCallDepth: 32,
		MaxInstances: 128,
		MaxSequences: 512,
		MaxFindings:  1024,
	}
}

func (o Options) concurrencyOptions() concurrency.Options {
	if o.Depth != DepthDeep {
		return concurrency.Options{}
	}
	return concurrency.Options{
		Flow:                o.flowOptions(),
		MaxTraces:           1024,
		MaxEventsPerFunc:    8192,
		MaxAccessesPerTrace: 4096,
		MaxSections:         1024,
		MaxFindings:         512,
		MaxFlowQueries:      512,
		MaxPairChecks:       131072,
		MaxLockPairs:        8192,
		MaxDiagnostics:      512,
	}
}

func (o Options) authProtoOptions() authproto.Options {
	if o.Depth != DepthDeep {
		return authproto.Options{}
	}
	return authproto.Options{
		MaxSourceDepth:     5,
		MaxSourceFunctions: 128,
	}
}
