# Global Analysis Budgets, Cancellation & Degraded Results

## 1. Budget Categories

- **Per-Analyzer Timeout**: Default 10m (`--semantic-timeout`). Interrupted analyzer is
  marked `failed` or `timeout`.
- **Frontend Load Timeout**: Default 15m (`LoadTimeout`). Load aborted; analyzers skipped;
  `LoadError` recorded.
- **Concurrency Semaphore**: Default `GOMAXPROCS` (`--semantic-max-parallel`). Bounded
  parallel worker execution.
- **Flow Max Origins**: Default 16 (`flow.MaxOrigins`). Sorted origin truncation; sets
  `Truncated = true`.
- **Concurrency Step Budget**: Default 1,000 (`MaxSteps`). Exploration capped with explicit
  truncation diagnostic.
- **Typestate Transition Limit**: Default 500 (`MaxTransitions`). Cyclic paths terminated;
  diagnostics record cutoff.
- **Plugin Timeout**: Default 30s (`DefaultPluginTimeout`). Process group killed via
  `SIGKILL` (`-pid`).
- **Plugin Output Buffer**: Default 1 MiB (`maxPluginOutput`). Buffer capped to prevent
  unbounded memory allocation.

---

## 2. Cancellation Mechanics

When context cancellation occurs (`SIGINT`, timeout, or budget exhaustion):
1. **Immediate Termination**: Active analyzers exit promptly at their next iteration check.
2. **Subprocess Group Cleanup**: On Unix, `syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)`
   terminates the entire process tree.
3. **No Hanging Work**: Worker goroutines release semaphore permits immediately.

---

## 3. Degraded Results & CI Exit Invariants

Under partial or aborted analysis, `m3tal-review` strictly enforces:
- `report.Analysis.Status = "degraded"` or `"failed"`
- `report.Passed = false`
- `report.Summary = "Review degraded..."`

**Invariant**: Incomplete analysis NEVER produces a passing verdict (`Passed = true`).
CI systems reliably catch build failures, timeouts, and resource-exhausted analysis.
