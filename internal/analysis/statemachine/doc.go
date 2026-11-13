// Package statemachine implements declarative state-machine contracts
// and bounded invariant evaluation over the engine-neutral semantic
// program model (internal/semantic).
//
// A contract (schema version "statemachine/1", see
// docs/statemachine-contracts.md) declares states, events,
// transitions with guards and effects, tracked fields (counters,
// timestamps, flags), named inputs, and invariants. Contracts bind to
// program entities structurally — function IDs, package paths,
// receiver types, declared types — never by name alone; unbound and
// ambiguous bindings are reported as diagnostics, not guessed.
//
// Evaluation (Evaluate) explores reachable control-flow paths through
// the program with explicit backtracking: contract events fire at
// bound call sites, guards and effects update per-instance machine
// state, and invariants are checked after every transition. Instance
// identity is resolved through the flow analyzer's place facts
// (globals and allocation sites), so the same resource is tracked
// across function boundaries. All exploration is bounded (steps, call
// depth, instances, sequences, findings) and every bound is reported
// through analysis.Budget entries and diagnostics.
//
// Honesty guarantees:
//
//   - Guard and invariant expressions use three-valued logic;
//     unknown operands make results unknown, and unknown guards are
//     treated as *possibly* enabled (may-analysis).
//   - Findings are StatusProven only when the violating path carried
//     no unknowns and the entire evaluation completed within budgets;
//     otherwise they are StatusPotential.
//   - Unbound contracts, unreachable states, unsupported expressions,
//     ambiguous bindings, and exhausted budgets are first-class
//     diagnostics — nothing is silently skipped.
//
// For property-based and model-based tests, BoundContract.NewRuntime
// exposes the same step logic as a deterministic interpreter:
// synthetic EventInput sequences can be driven directly and
// StepResult.Violation observed without any program analysis.
package statemachine
