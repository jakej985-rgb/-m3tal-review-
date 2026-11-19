# Semantic Analyzer Soundness Matrix & Verification

## 1. Overview & Verification Philosophy

`m3tal-review` semantic analyzers perform sound, bounded static analysis over an
engine-neutral typed program model (`internal/semantic`). The analyzers prioritize
**honesty over false certainty**:
- When code is outside an analyzer's formal modeling boundaries, the engine emits
  structured `Diagnostic` messages (e.g. unmodeled dynamic dispatch, external library calls,
  budget exhaustion).
- Incomplete analysis is marked as degraded in the report envelope (`analysis.status =
  "degraded"` or `report.passed = false`), guaranteeing that partial checks cannot be
  mistaken for a clean security pass.
- Finding epistemic status (`proven` vs `potential`) is strictly distinguished in finding
  metadata.

---

## 2. Analyzer Soundness Matrix

### Concurrency Analyzer
- **Domain**: Shared state, check-then-act, lock ordering, unmatched unlocks.
- **Epistemic Status**: `potential` (inherent may-analysis across interleavings).
- **Soundness Guarantees**: Flags unprotected group accesses & lock inversions.
- **Documented Limitations**: Channels, atomics, WaitGroups, and closures emit diagnostics.

### Typestate Analyzer
- **Domain**: Linear / affine resource lifecycles (single use, double consume).
- **Epistemic Status**: `proven` & `potential`.
- **Soundness Guarantees**: Proves double-consume along explicit call paths and aliases.
- **Documented Limitations**: Dynamic dispatch and reflection emit assumptions.

### State Machine Analyzer
- **Domain**: Declarative FSM contracts & state transition invariants.
- **Epistemic Status**: `proven` & `potential`.
- **Soundness Guarantees**: Bounded state exploration up to step/depth limits.
- **Documented Limitations**: Bodiless callees noted as external; budgets truncate.

### Flow Analyzer
- **Domain**: Interprocedural dataflow & taint propagation.
- **Epistemic Status**: Conservative fixpoint.
- **Soundness Guarantees**: Monotonic transfer functions guarantee termination.
- **Documented Limitations**: Unsafe pointer casts and assembly are unmodeled.

### AuthProto Analyzer
- **Domain**: Nonce freshness, replay safety, transcript binding.
- **Epistemic Status**: `proven` & `potential`.
- **Soundness Guarantees**: Flags static/weak nonces and missing transcript binds.
- **Documented Limitations**: Custom crypto primitives emit unmodeled diagnostics.

### Protocol Analyzer
- **Domain**: Protocol handshake and packet sequence validation.
- **Epistemic Status**: `proven` & `potential`.
- **Soundness Guarantees**: Validates declared protocol state transitions.
- **Documented Limitations**: Raw unstructured packet streams cannot be parsed.

---

## 3. Epistemic Status & Confidence Propagation

1. **Status Proven (`proven`)**:
   - The analyzer has verified that an execution path definitely violates the invariant.
   - Path conditions, argument facts, and call sites are fully resolved.

2. **Status Potential (`potential`)**:
   - A violation exists along at least one may-path, but branch feasibility or alias
     resolution cannot be determined with complete certainty.
   - Interleaving analysis in concurrency is always classified as `potential` because
     runtime thread scheduling is nondeterministic.

3. **Incomplete Coverage & Degradation**:
   - If an analyzer encounters unsupported constructs (such as dynamic interface dispatch,
     reflection, or assembly routines), it records an `Assumption` or `Diagnostic`.
   - If budget limits (step count, call depth, memory) are reached, `Truncated = true` is set,
     and the run is treated as degraded in downstream review reports.

---

## 4. Test Matrix & Adversarial Fixture Inventory

Each analyzer is paired with curated fixtures covering positives, clean negatives, and
adversarial edge cases:

- **`internal/analysis/concurrency`**:
  - `TestAdversarial_ClosureLoopCapture`: Goroutine closures over collection items.
  - `TestAdversarial_UnmodeledDynamicCall`: Unresolved interface dispatch diagnostics.
  - `TestAdversarial_BuildTagIgnored`: Handling `//go:build ignore` without crash.
  - `TestLockOrdering`: Inverted mutex acquisition detection (`ba` vs `ab`).
  - `TestUnmatchedUnlock`: Calling unlock on unheld lock.
  - `TestAtomicOps`: Explicit diagnostics on atomic primitives.

- **`internal/analysis/typestate`**:
  - `testdata/aliases`: Re-use detection through pointer aliasing.
  - `testdata/branches` & `testdata/branch-exclusive`: Branch path sensitivity.
  - `testdata/helper-indirection`: Interprocedural detection across helper functions.
  - `testdata/early-return`: Resource leaks and unconsumed states on early returns.
  - `testdata/invalid-reset`: Calling reset from unpermitted lifecycle states.

- **`internal/analysis/authproto`**:
  - `testdata/replay` vs `testdata/replay-safe`: Replay detection and safe caches.
  - `testdata/static-nonce` & `testdata/weak-nonce`: Insufficient entropy in handshakes.
  - `testdata/transcript-binding`: Missing hash bindings in challenge-response.
  - `testdata/unmodeled`: Explicit uncertainty reporting for unrecognized crypto routines.
