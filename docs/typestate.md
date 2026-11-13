# Typestate analysis for single-use resources (`typestate/1`)

`internal/analysis/typestate` detects invalid resource lifecycle
behavior — beginning with single-use challenges, nonces, tokens, and
similar credentials that may be consumed at most once along any one
execution path. It is built on the declarative state-machine contract
framework (`internal/analysis/statemachine`, `statemachine/1`) and the
interprocedural flow summaries (`internal/analysis/flow`); this
document describes the thin spec layer that derives lifecycle
contracts from a resource type plus explicitly bound operations.

Spec documents are YAML (`.yaml`/`.yml`); JSON parses as a YAML
subset. The schema version is mandatory:

```yaml
schema_version: typestate/1
```

## Document structure

```yaml
schema_version: typestate/1
id: challenge-single-use          # stable ID used in findings/diagnostics
name: Single-use auth challenge   # optional
resource:                         # optional subject type binding
  type: "example.com/app.Challenge"   # "[pkg/path][*].Name"

operations:                       # required, at least one
  - kind: consume                 # "consume" | "use" | "reset"
    function:                     # structural binding — see below
      name: Consume
      receiver: "example.com/app.Challenge"
    subject_arg: 0                # aligned arg index (0 = receiver/1st param); -1 = shared instance
  - kind: use
    function: { name: Check, receiver: "example.com/app.Challenge" }
  - kind: reset
    function: { name: Reset, receiver: "example.com/app.Challenge" }

entry:                            # optional exploration seeds
  - id: "example.com/app.main"
```

### Operation kinds

Each spec derives a fixed two-state contract —
`available` (initial) → `consumed` — in which every operation kind has
exactly one legal source state:

| kind     | legal in     | effect                    | violation when fired elsewhere        |
|----------|--------------|---------------------------|---------------------------------------|
| `consume`| `available`  | → `consumed`              | `typestate-double-consume`            |
| `use`    | `available`  | stays `available`         | `typestate-use-after-consume`         |
| `reset`  | `consumed`   | → `available` (re-arm)    | `typestate-invalid-reset`             |

Any bound operation firing outside its legal state is an
illegal-transition finding. There is no permissive fallback: a
`consume` in `consumed`, a `use` in `consumed`, and a `reset` in
`available` are all violations. Legal sequences such as
`consume → reset → consume` (reissue) are accepted.

`name` on an operation optionally overrides the derived event label
(used in messages/metadata only). When omitted it defaults to the
kind, suffixed `-2`, `-3`, ... on collision. **Names never carry
semantics**: a Go function called `Consume` is analyzed only when the
spec binds it structurally; an unbound or ambiguous binding is a
diagnostic, never a guess.

### Structural binding

`function` uses the same `FunctionSpec` shape as `statemachine/1`
contracts: `id` (exact semantic function ID) or `name` filtered by
`package` and `receiver`. Zero matches → "unbound" diagnostic; multiple
matches → "ambiguous" diagnostic. `subject_arg` selects which aligned
call argument identifies the resource instance (index 0 is the receiver
for methods, the first parameter for functions).

## What is tracked

Resource identity is a may-key computed from the flow analyzer's place
facts — package globals, allocations, parameters chased back through
recorded call sites — so the same resource is tracked:

- across **aliases** (`alias := c` propagates the same place set),
- through **helper calls** (parameter places resolve to caller
  actuals),
- across **branches and merges** (the evaluator explores paths with
  backtracking; machine state is part of the visited key, so
  `if flag { consume(c) }; consume(c)` reports the double consume on
  the `flag` path while `if/else` single consumes stay clean),
- through **early returns** (only paths that actually reach the second
  consume are flagged).

Fields reached through a parameter collapse to the parameter's place
(the flow model does not retain field indices), so two resources held
in fields of the same struct may merge into one instance — reported
as potential, never silently proven.

## Findings and honesty

Violations are emitted as `analysis.Finding` with
`Analyzer: "typestate"`, `Trace: state-transition`, and rule IDs
`typestate-double-consume`, `typestate-use-after-consume`,
`typestate-invalid-reset` (fallback `typestate-illegal-transition`).
Evidence is the machine's transition history: availability →
consumption → the rejected invalid operation, each step carrying its
call-site span and bound callee.

Status rules (inherited from the statemachine evaluator, tightened):

- `proven` only when the violating path carried no unknowns **and**
  evaluation finished within budgets;
- `potential` when the path crossed a dynamic/unresolved call, a
  bodiless callee, an unknown guard, **or when instance identity could
  not be fully resolved** (roots containing `?` — e.g. resources
  arriving as parameters of never-called functions or through call
  results the flow model cannot name);
- budgets (`max-steps`, `max-call-depth`, `max-instances`,
  `max-findings`, `max-sequences`) are reported through
  `Result.Budgets`/`Diagnostics`; exhaustion marks the result truncated
  and forbids `proven`.

## Precision limits

- Identity through **call results** is approximate: a resource returned
  by a helper may resolve to an unknown instance key, merging distinct
  resources — findings degrade to `potential`.
- Resources reachable only through **unresolved calls** (function
  values, interfaces without CHA edges, external code) are not tracked;
  the path is marked unknown.
- The lifecycle is deliberately minimal (two states, three operation
  kinds). Richer protocols — multi-use quotas, expiry timestamps,
  per-state guards — belong in hand-written `statemachine/1` contracts,
  which the typestate spec compiles down to anyway.

## Usage

```go
spec, err := typestate.ParseSpec(specYAML)
res, err := typestate.Analyze(ctx, prog, []*typestate.Spec{spec}, statemachine.Options{})
// res.Findings are analysis.Finding values; res.Diagnostics,
// res.Budgets, res.Truncated, res.Assumptions carry the rest.
```

`typestate.BuildContract(spec)` exposes the derived
`statemachine/1` contract for inspection or direct evaluation.
