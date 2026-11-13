# Concurrency and atomicity analysis

`internal/analysis/concurrency` detects shared-state defects that ordinary
data-race checkers miss — most importantly **check-then-act sequences split
across individually correct critical sections** (logical atomicity / TOCTOU
violations). A mutex can make every individual access race-free while the
*sequence* "check, then act on the checked value" is still non-atomic.

The analyzer is language-neutral; Go synchronization primitives are
recognized at the edges of the package.

## Pipeline

1. **Data flow.** The existing `internal/analysis/flow` may-analysis
   provides read/write summaries, place facts (globals, parameters,
   locals), and value dependencies. The concurrency analyzer consumes
   `PlacesOf`/`DepsOf`/`ActualsFor`/`CallSites`/`Flow` rather than
   re-deriving them.
2. **State keys.** Every accessed location is reduced to a canonical
   `stateKey`: either a set of *place atoms* (global value IDs, parameter
   slots scoped by function, locals) or *origin atoms* (parameter/free
   variable/unknown dependence origins). Parameter indices are
   canonicalized through observed argument aliasing (`f(s, s)` unions
   parameters 0 and 1 — a documented may-analysis).
3. **Events.** Per function, instructions become events: shared-state
   reads/writes (loads, stores, field accesses, map ops, `delete`,
   `copy`), lock acquires/releases, atomic accesses, goroutine spawns,
   channel ops, and opaque-call notes. Calls are inlined to a bounded
   depth so helpers and methods contribute their effects at the call
   site; unresolved dynamic calls are noted, not guessed.
4. **Traces.** Events are replayed per function root (plus `go`
   statement targets as separate goroutine contexts). The replay tracks
   held locksets, critical-section instances, and the shared-state
   accesses inside each section.
5. **Findings.** Candidate check-then-act pairs, unheld unlocks, and
   lock-order inversions are emitted as `analysis.Finding`s with
   evidence, lock-sequence traces, and honest statuses.

## What is modeled

- **`sync.Mutex` / `sync.RWMutex`** — recognized via the receiver's
  semantic type (`sync.Mutex`, `sync.RWMutex`, or pointers to them) and
  method name (`Lock`, `Unlock`, `RLock`, `RUnlock`, `TryLock`,
  `TryRLock`). Lock/unlock calls contribute mutex-keyed acquire/release
  events; critical sections are the instruction ranges between them,
  including `defer Unlock` (released at function exit).
- **`sync/atomic`** — `Load*` reads, `Store*` writes, everything else
  (`Add*`, `Swap*`, `CompareAndSwap*`) reads and writes. Each atomic op
  is modeled as a *single* access; sequences of atomic ops are **not**
  treated as atomic groups (a diagnostic notes this).
- **`go` statements** — each `go` target becomes a separate goroutine
  root; functions reachable only from it get their own context.
- **Channels** — `close` and channel ops are noted as synchronization
  the analyzer does not model as mutual exclusion.
- **Globals** — sharing is established when flow summaries (or the
  analyzer's own access events, which cover atomic ops flow treats as
  opaque) show a global place used under two or more distinct goroutine
  contexts.

## Findings

| Rule | Status | Meaning |
| --- | --- | --- |
| `concurrency-check-then-act` | `potential` | A read that may influence a branch ("check") and a later write to conflicting shared state ("act") execute under different critical sections or none. The evidence names the shared state, both critical sections (or their absence), and a representative interleaving. |
| `concurrency-unmatched-unlock` | `potential` | An unlock releases a mutex the replayed event order does not show as held on some path — a panic or wrong-section release risk. |
| `concurrency-lock-order` | `potential` | Two mutexes are acquired in opposite orders in different traces that may run concurrently — a deadlock candidate. |

All interleaving-based findings are `potential`: the analyzer shows a
*possible* schedule, not a proven one. `proven` is reserved for cases
with complete, untruncated evidence.

A check-then-act finding requires **both** halves: established shared
state (the location is reachable from ≥2 goroutine contexts) **and** a
conflicting pattern. Merely holding two locks, or two unrelated accesses
to the same state, is not flagged. Reads whose outputs are pointer-like
references are excluded from "check" classification — loading a captured
pointer is address plumbing, not a data check.

## Limitations (surfaced as diagnostics)

- **Opaque external calls** — calls into functions without bodies
  (including mutex/atomic stubs) have unknown effects; a diagnostic
  counts them.
- **Unsupported synchronization** — recognized `sync` primitives that
  are not mutexes or atomics (e.g. `sync.Once.Do`, `sync.WaitGroup`,
  `sync.Map`, `x/sync/semaphore`) produce an *unsupported
  synchronization primitive* diagnostic rather than silent treatment.
- **Atomic groups** — each `sync/atomic` op is atomic alone; a
  check-then-act built from several atomic ops is still flagged because
  the *sequence* is not atomic.
- **May-analysis coarseness** — parameter aliasing is unioned globally
  (an alias at one call site merges parameters everywhere); places that
  flow cannot distinguish collapse to origins or `unknown`, which are
  treated conservatively.
- **Bounded** — event counts, trace counts, inline depth, flow queries,
  findings, and diagnostics are all capped by `Options`; hitting a
  budget sets `Result.Truncated` and/or diagnostics.
- **`go test -race`** is complementary, not implemented: it detects
  actual data races on a specific run, while this analysis reasons about
  possible interleavings statically. Findings' remediation notes suggest
  race-detector runs for confirmation.

## Usage

The package is not yet wired into the review pipeline (tracked
separately). Programmatic use:

```go
prog, diags := golang.Load(ctx, golang.Options{Dir: dir})
an := concurrency.NewAnalyzer(prog, concurrency.Options{})
res := an.Analyze(ctx)
// res.Findings, res.Shared, res.Sections, res.Diagnostics
```

See `concurrency_test.go` for synthetic-module fixtures covering split
vs. single critical sections, aliases, helpers, early unlocks, nested
calls, RWMutex, globals, lock ordering, unmatched unlocks, atomics, and
unknown synchronization.
