# Performance, Memory & Scalability Baseline

## 1. Overview & Methodology

This audit establishes reproducible performance baselines for `m3tal-review` across
varying repository sizes and diff volumes.

The benchmark suite (`internal/benchmark/scalability_test.go`) evaluates synthetic
repositories under Go's standard benchmark harness (`go test -bench=. -benchmem`):
- **Small Repository**: 10 files, ~500 lines changed (typical PR/commit).
- **Medium Repository**: 50 files, ~5,000 lines changed (feature branch merge).
- **Large Repository**: 200 files, ~20,000 lines changed (large refactor / multi-package change).

---

## 2. Baseline Measurements

Hardware: x86_64 Linux 8-core CPU, 16GB RAM.

| Benchmark Tier | Files | Lines | Latency / Op | Allocations / Op | Memory / Op |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Small Repo** | 10 | 500 | ~20 ms | 4,549 allocs | ~2.7 MB |
| **Medium Repo** | 50 | 5,000 | ~188 ms | 22,091 allocs | ~24.0 MB |
| **Large Repo** | 200 | 20,000 | ~2.24 s | 4.3M allocs | ~5.0 GB peak |

---

## 3. Scalability Characteristics & Hot Paths

1. **Rule Evaluation Throughput**:
   Pattern-matching rules scale linearly with total diff hunk lines ($O(N)$). Regex patterns
   are pre-compiled during engine initialization, avoiding re-compilation per hunk.

2. **Memory Growth & Slicing**:
   Diff parsing constructs zero-copy line slices where possible. In massive diffs (> 20,000
   lines), peak memory is dominated by tokenization and AST generation. Global analysis
   budgets (`internal/analysis/pipeline`) prevent runaway memory expansion by bounding
   allocation limits.

3. **Execution Determinism**:
   Verified by `TestScalability_DeterminismAcrossRuns`: running consecutive reviews over the
   same inputs yields byte-identical finding orders and counts.

---

## 4. Performance Regression Thresholds

To maintain high throughput in CI/CD developer feedback loops:
- Small PRs (< 20 files): **Target < 50 ms** (hard limit: 200 ms).
- Medium PRs (20–100 files): **Target < 500 ms** (hard limit: 2.0 s).
- Large Refactors (100–500 files): **Target < 5.0 s** (hard limit: 15.0 s).

Any PR that degrades latency by $> 25\%$ without architectural justification must be
flagged for review.
