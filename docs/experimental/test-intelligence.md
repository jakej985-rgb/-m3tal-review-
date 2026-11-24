> **Experimental status.** This feature is implemented and unit-tested but is not wired into the CLI. See `internal/experimental/README.md`.

# Test Intelligence & Remediation Verification

## Overview

The `m3tal-review` test intelligence subsystem bridges static analysis findings and test suites.
It maps discovered security and reliability findings to relevant tests, flags untested
security-critical paths, produces bounded regression test proposals, and verifies remediations
using targeted tests and re-analysis.

## Core Capabilities

### 1. Test Discovery & Classification

Test targets are discovered by parsing test file abstract syntax trees (ASTs). Functions are
categorized into deterministic kinds:
- **`unit`**: Standard `Test*` functions exercising isolated units.
- **`regression`**: Dedicated test functions (`Test*Regression*`) asserting defect fixes.
- **`integration`**: Broad integration tests (`Test*Integration*`, `Test*E2E*`).
- **`benchmark`**: Performance benchmarks (`Benchmark*`).
- **`fuzz`**: Property-based and fuzzing entrypoints (`Fuzz*`).

### 2. Finding to Test Association

Findings are associated with test targets via multi-tiered deterministic matching:
- **`direct_symbol` (High Confidence)**: Test name explicitly targets the affected function or symbol.
- **`package_colocated` (High/Low Confidence)**: Test resides in the co-located test file (e.g.
  `handler_test.go` for `handler.go`) or the same package directory.
- **`evidence_trace` (Medium Confidence)**: Test covers a function or file referenced along an
  interprocedural evidence trace.

### 3. Coverage Gap Assessment

Security findings without adequate testing present severe regression hazards:
- **`CRITICAL_GAP`**: Critical or high severity findings with zero associated tests (`CoverageNone`).
- **`HIGH_GAP`**: High-severity findings with only general package tests (`CoverageWeak`).
- **`MEDIUM_GAP`**: Tests exist, but lack a dedicated regression test (`TestKindRegression`).

### 4. Non-Binding Test Suggestions

For uncovered findings, the engine generates regression test proposals:
- Includes function naming conventions: `Test<Symbol>_Regression_<Rule>`.
- Provides boundary condition assertions.
- **Epistemic Boundary**: Proposals are audit-only skeletons for developer review. They are
  *never* committed silently or executed without explicit authorization.

### 5. Remediation Verification & Epistemic Limits

Fix verification validates repairs through dual-engine confirmation:
1. Targeted test execution under bounded timeouts and safe sandboxing.
2. Differential re-analysis to confirm the original finding is resolved.
3. Collateral check to verify no new defect findings were introduced.

#### Epistemic Honesty Principle
> "Passing tests demonstrate absence of observed test failures, not absence of defects or formal
> correctness. Static re-analysis confirms the modeled rule pattern is no longer flagged under
> configured heuristics."
