// Package typestate implements typestate analysis for single-use
// resources and lifecycle violations on top of the declarative
// state-machine contract framework (internal/analysis/statemachine,
// schema statemachine/1) and the interprocedural flow summaries
// (internal/analysis/flow).
//
// A typestate spec (schema version "typestate/1", see
// docs/typestate.md) declares a resource type and a small set of
// lifecycle operations — consume (single use), use (read while
// available), and reset (re-arm after consumption). Each operation
// binds to program functions *structurally* (function ID, name
// filtered by package/receiver — never name semantics alone): a
// function named Consume means nothing unless the spec binds it.
//
// Analyze derives one statemachine contract per spec —
//
//	available --consume--> consumed
//	available --use-----> available   (use-after-consume is illegal)
//	consumed  --reset---> available   (reset while available is illegal)
//
// — and runs the bounded statemachine evaluator. Resource identity is
// tracked across aliases, parameters, returns, fields, and helper
// calls through the flow analyzer's place facts; branches and merges
// are explored with backtracking, so state propagates correctly along
// every feasible path.
//
// Honesty guarantees (inherited and tightened):
//
//   - A lifecycle operation firing outside its legal state is an
//     illegal-transition finding with a state-transition evidence
//     trace from availability through the invalid use.
//   - Findings are StatusProven only when the violating path carried
//     no unknowns and evaluation completed within budgets; unresolved
//     instance identity, dynamic calls, bodiless callees, and
//     exhausted budgets keep findings at StatusPotential.
//   - Unbound or ambiguous operation bindings are diagnostics, never
//     guesses.
package typestate
