# Semantic analysis pipeline

`internal/analysis/pipeline` integrates the semantic engines
(`internal/analysis/*`) into the `review` and `audit` commands. It is
**opt-in**: nothing runs unless `--semantic` is passed or
`semantic.enabled` is set in the user config, because loading a typed,
SSA-based program model with `go/packages` is expensive and only makes
sense for Go repositories.

## What one run does

1. **Shared frontend load.** The Go frontend
   (`internal/semantic/golang.Load`) loads the repository's program
   model **once**; every enabled analyzer shares the same
   `*semantic.Program`. A `pipeline.Loader` can cache the program
   across runs in embedded/watch use.
2. **Contract discovery.** `*.yaml`/`*.yml` files under the contract
   directory (default `<repo>/.m3tal/contracts`, recursive, sorted,
   size/count-capped) are routed by their mandatory `schema_version`:
   - `statemachine/1` → `statemachine` evaluator
   - `typestate/1` → `typestate` single-use resource specs
   - `authproto/1` → modeled auth/crypto protocol checks
   - `protocol/1` → versioned protocol snapshots; all pairs of loaded
     versions are compared via `protocol.EvaluateMatrix`
3. **Bounded parallel execution.** Enabled analyzers run concurrently
   under a semaphore (`--semantic-max-parallel`, default
   `GOMAXPROCS`), each with a per-analyzer timeout
   (`--semantic-timeout`, default 10m). Results are collected in
   registration/dependency order — never completion order — so output
   is deterministic. Analyzer panics, errors, and timeouts become
   diagnostics and check results; they never abort the run or corrupt
   other analyzers' results.
4. **Normalization.** All findings use the shared `analysis.Finding`
   contract (evidence traces, proven/potential/unverified status,
   truncation) and are adapted into the legacy report shape with
   `category: "semantic"`. Program-load diagnostics, contract parse
   problems, unsupported constructs, and budget exhaustion surface as
   `analysis.Diagnostics`.

## Enabled analyzers

| Name | Engine | Input |
| ---- | ------ | ----- |
| `flow` | `internal/analysis/flow` | program only; emits summaries + diagnostics (no findings) |
| `statemachine` | `internal/analysis/statemachine` | `statemachine/1` contracts |
| `typestate` | `internal/analysis/typestate` | `typestate/1` specs |
| `concurrency` | `internal/analysis/concurrency` | program only |
| `authproto` | `internal/analysis/authproto` | `authproto/1` contracts |
| `protocol` | `internal/analysis/protocol` | ≥2 `protocol/1` snapshots |

Contract-driven analyzers report `skipped` when their family has no
input; `protocol` requires at least two snapshots to compare.

## CLI

```
m3tal-review review --semantic [--semantic-analyzers a,b,c]
                    [--semantic-contracts DIR] [--semantic-max-parallel N]
                    [--semantic-timeout 10m] [--semantic-depth standard|deep]
                    [--semantic-tests]
m3tal-review audit  <same flags>
```

- `--semantic` / `--no-semantic` — enable or disable (default: off).
- `--semantic-analyzers` — comma-separated subset of the names above;
  default is all six.
- `--semantic-contracts` — contract directory (default
  `.m3tal/contracts` under the repository root).
- `--semantic-max-parallel` — concurrency bound (default
  `runtime.GOMAXPROCS`).
- `--semantic-timeout` — per-analyzer Go duration (default 10m).
- `--semantic-depth` — `standard` (engine defaults) or `deep` (raised
  exploration/summary budgets; slower, more thorough).
- `--semantic-tests` — include `*_test.go` package variants in the
  program model.

User config (`~/.config/m3tal-review/config.json`) accepts a
`semantic` object mirroring the flags:

```json
{
  "semantic": {
    "enabled": true,
    "analyzers": ["typestate", "concurrency"],
    "contract_dir": ".m3tal/contracts",
    "max_parallel": 4,
    "timeout": "10m",
    "depth": "standard",
    "tests": false
  }
}
```

Explicit flags always override config values.

## Report output

Semantic findings appear in `findings[]` with `category: "semantic"`,
their analyzer in `analyzers[]`, the analysis status/truncation in
`metadata.analysis_status` / `metadata.analysis_truncated`, and the
evidence trace flattened into `evidence[]`. The report's `analysis`
section records:

- `status`: `completed`, `degraded` (analyzer failure, truncation, or
  error diagnostics), or `failed` (frontend could not load a program).
- `program`: package/function/value counts of the shared model.
- `analyzers[]`: per-analyzer `CheckResult` entries (category
  `semantic`), including `skipped` contract-driven analyzers.
- `diagnostics[]`: merged, deterministically sorted analysis
  diagnostics — this is where "analysis could not complete" is
  reported honestly.

Pattern/inventory rules remain a separate low-cost tier: they run on
the diff/working tree exactly as before, concurrently inside
`review.Engine`, and are unaffected by the semantic pipeline.

## External tools

Mature Go tooling is reused rather than rebuilt: the `repository-lint`
rule wraps `gofmt`/`go vet`/`staticcheck`/`golangci-lint`, and
`--profile full` runs `gofmt`, `go vet ./...`, and `go test ./...` as
confidence checks. `--with-tools` adds `gitleaks`, `gosec`, and
`osv-scanner` when installed. The semantic pipeline complements these;
it does not re-implement them.

## Failure behavior

- **No Go toolchain / unloadable module**: the frontend load fails →
  `analysis.status: "failed"`, a `semantic-frontend` check result, an
  error diagnostic, and every enabled analyzer marked `skipped`. The
  rest of the review (pattern rules, tools, plugins) is unaffected.
- **Contract parse errors**: diagnostics; valid sibling contracts
  still run.
- **Analyzer panic/error/timeout**: isolated to that analyzer's
  `AnalyzerResult`; other analyzers' findings are intact.
- **Budget exhaustion**: findings are never promoted past
  `potential`; truncation is recorded in diagnostics and finding
  metadata.

## Limitations

- The program model covers the Go packages selected by the frontend
  (default `./...`, bounded by `MaxPackages`); findings are
  whole-program, not limited to the diff — use `--include`/`--exclude`
  or policy overrides to scope them.
- `protocol` matrix versions are the snapshot labels present in the
  contract directory; it cannot know about deployed versions that have
  no checked-in snapshot (reported as diagnostics).
- The contract cache (`pipeline.Loader`) is process-lifetime and never
  invalidated; long-lived embedders should create a new `Loader` or
  call `Invalidate` when the tree changes.
