# Declarative state-machine contracts (`statemachine/1`)

State-machine contracts let a project state important behavioral
properties explicitly — resource lifecycles, attempt counters,
timestamps, expiration windows, reset behavior, access conditions — in
a small, versioned, language-neutral format. The
`internal/analysis/statemachine` package parses, validates, binds, and
evaluates them against the semantic program model
(`internal/semantic`); it never depends on Go syntax except through the
neutral model's escape hatches.

Contract documents are YAML (`.yaml`/`.yml`); JSON parses as a YAML
subset. The schema version is mandatory:

```yaml
schema_version: statemachine/1
```

Any other value is rejected. Additive fields may be introduced without
a version bump; incompatible changes require a new `statemachine/N`
schema handled by a new parser.

## Document structure

```yaml
schema_version: statemachine/1
id: token-consume                # stable ID used in diagnostics/findings
name: Single-use token           # optional, human-readable
description: ...                 # optional

resource:                        # optional subject type binding
  type: "example.com/x.Token"    # "[pkg/path][*].Name"

states:
  - name: fresh
    initial: true                # exactly one state must be initial
  - name: consumed

events:
  - name: consume
    function:                    # structural binding (see below)
      name: Consume
      receiver: "example.com/x.Token"
    subject_arg: 0               # which argument identifies the instance

transitions:
  - event: consume
    from: fresh                  # state name, "any", or a list
    to: consumed                 # omit to stay in the same state
    guard: "attempts < 3"        # optional expression
    effects:                     # optional state updates
      - inc: attempts
      - set: last_attempt = arg[1]
      - reset: [attempts, locked_until]

invariants:
  - expr: "attempts <= max_attempts"
    message: "optional override for the violation message"

fields:                          # tracked data (counters, timestamps, flags)
  - name: attempts
    kind: int                    # "int" (default) or "bool"
    initial: 0

inputs:                          # named per-trigger values for expressions
  - name: now
    arg: 1                       # aligned argument index, or:
    # global: "example.com/x.nowVar"   # symbolic global (always unknown)

entry:                           # exploration seeds; default: all functions with bodies
  - id: "example.com/x.main"

on_unhandled: report             # "report" (default) or "ignore"
```

### States

`states` is a non-empty list; exactly one entry must set
`initial: true`. State names must be unique non-empty strings.

### Events and transitions

`events` names the occurrences a contract cares about. An event may
bind to a program function via `function:` (see *Binding*). Events
without bindings never fire during program evaluation but remain
usable with `Runtime` for model-based tests.

`transitions` maps `(from-state(s), event)` to a target state with an
optional `guard` and `effects`. `from` accepts a state name, the
keyword `any` (all states), or a list of state names. Transitions are
tried in declaration order; the first whose guard is **not definitely
false** fires. Omitting `to` keeps the current state.

### Guards, invariants, and the expression language

Guards and invariants share one small expression language:

```
expr    := orExpr
orExpr  := andExpr ( "||" andExpr )*
andExpr := cmpExpr ( "&&" cmpExpr )*
cmpExpr := addExpr ( ("=="|"!="|"<"|"<="|">"|">=") addExpr )?
addExpr := mulExpr ( ("+"|"-") mulExpr )*
mulExpr := unary ( ("*"|"/"|"%") unary )*
unary   := "!" unary | "-" unary | primary
primary := number | "string" | true | false | name | "arg" "[" N "]" | "self" | "(" expr ")"
```

Identifiers resolve against declared `fields` and `inputs`; reading an
undeclared name is a contract error. Special forms:

- `arg[N]` — the Nth **aligned call argument** of the triggering
  event. Alignment matches the flow analyzer: index 0 is the receiver
  for methods, otherwise the first parameter.
- `self` — the event's `subject_arg` value (the resource instance).

All operations use **three-valued logic**: any operand that is
unknown makes the result unknown. Unknown guards are treated as
*possibly enabled* (may-analysis) and recorded as assumptions; unknown
invariants are treated as satisfied (a breach must be definite to be
reported).

### Effects

Each effect is a single-key mapping:

- `inc: field` / `dec: field` — integer counter update. Unknown or
  non-integer fields are left unchanged.
- `set: field = expr` — assign an expression result (may be unknown).
- `reset: field` or `reset: [f1, f2]` — restore declared initial values.

Integer fields saturate at the evaluator's `MaxFieldValue` bound so
counter loops terminate; saturation is an documented abstraction, not
a truncation.

### Fields and inputs

`fields` declare tracked state: `kind: int` (default) or `kind: bool`,
with `initial` values. Fields may also be introduced implicitly as int
fields by `inc`/`dec`/`set`/`reset` effects; reads in expressions must
still refer to declared names.

`inputs` bind a name to a per-trigger value: `arg: N` (aligned call
argument) or `global:` (a symbolic program global — always unknown
because the model does not track global values). Inputs are the
mechanism for timestamps and clocks: e.g. `now` bound to a `now`
parameter lets guards express `now >= locked_until`.

## Binding semantics

Contracts bind to the semantic program **structurally**:

- `function.id` — exact `semantic.Function.ID` match.
- `function.name` + optional `package` (import path) and `receiver`
  (`[pkg/path.]TypeName`, pointers unwrapped) — filtered candidate
  matching over modeled functions.
- `resource.type` — resolved against declared package types.
- `entry` — `FunctionSpec` list seeding path exploration; default is
  every modeled function with a body (non-synthetic).

A binding with **zero matches is "unbound"** and one with **multiple
matches is "ambiguous"**: both produce diagnostics and are never
guessed. If several events bind the same function, exploration forks
per event (may-analysis over the ambiguity). `subject_arg` selects the
aligned argument identifying the resource instance; `-1` selects the
contract's single shared instance.

## Instance identity

When `subject_arg >= 0`, the evaluator computes an instance key from
the data-flow place facts of the subject argument: package globals and
allocation sites are root identities, propagated backwards through
call parameters (bounded by `maxInstanceDepth`). The key is a *set* of
possible roots — a may-key that over-approximates when uniqueness
cannot be proven, so cross-function instance tracking works (e.g. a
global token consumed in a helper) without heap modeling.

## Evaluation model

`statemachine.Evaluate` runs the flow analyzer once, then explores
bounded control-flow paths per contract with explicit backtracking:

- At each call site, resolved callees (`Call.Callees`, with the
  function-value fallback) are explored as may-alternatives.
- Bound event functions fire their transition before the callee body
  is explored; caller continuation runs under each path's resulting
  machine state (full interprocedural path semantics).
- Exploration state is `(program point, call stack, machine
  configuration)`; revisits are pruned, loops with unchanged machine
  state terminate, and loops that keep mutating state are cut by
  budgets.
- Guards/effects/invariants run on the contract runtime shared with
  `Runtime`, so evaluation and model tests exercise identical logic.

### Budgets

`Options` bounds `MaxSteps` (instructions explored), `MaxCallDepth`,
`MaxInstances` (per contract; overflow merges into a reported `?`
bucket), `MaxFieldValue` (counter saturation), `MaxSequences`, and
`MaxFindings`. Every exhaustion produces an `analysis.Budget` entry, a
`limit` diagnostic, and `Result.Truncated=true`.

### Honesty rules

- A finding is `proven` only when its path carried no unknowns
  (unknown guards, unresolved dynamic calls, external callees) **and**
  the whole evaluation finished within budgets; otherwise `potential`.
- Unbound/ambiguous bindings, unreachable states (static graph
  analysis), states never covered, unsupported expressions, and budget
  exhaustion are all diagnostics — nothing is silent.

## Property-based / model-based testing route

`BoundContract.NewRuntime(instance)` returns a deterministic
`Runtime` implementing the same transition semantics without program
analysis:

```go
bc := statemachine.Bind(prog, contract) // or bindForTest with empty prog
rt := bc.NewRuntime("")
res := rt.Step(statemachine.EventInput{Name: "attempt", Args: []statemachine.Value{statemachine.Int(41)}})
// res.Applied, res.Violation (*Violation with Kind illegal-transition|invariant)
rt.State(), rt.Field("attempts"), rt.History(), rt.InvariantCheck()
```

This supports `testing/quick`-style generators, exhaustive sequence
enumeration, and replay of `Result.Sequences` event names.

## Limitations

- Instance keys are may-keys over places, not precise heap identities:
  two allocations at one site share a key, and values the flow
  analyzer cannot place collapse to `?` (merged conservatively).
- `arg[N]`/`self` values are known only for compile-time constants;
  everything else is unknown (three-valued logic keeps this honest).
- `go`/`defer` calls are explored like direct calls; goroutine
  interleavings and defer timing are not modeled.
- Defer/run-defers ordering, channels, and reflection are outside the
  contract semantics.
- Contracts are evaluated independently; cross-contract state is not
  shared.
