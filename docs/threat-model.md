# m3tal-review — Threat Model & Limitations

## What this tool is

m3tal-review is a **deterministic, heuristic, local** code reviewer. It parses
diffs (staged, unstaged, `--base`, patch files, or stdin) and applies ~95
pattern/AST rules plus language-aware slop analyzers. It makes no network
calls except when explicitly asked (`--with-tools` scanners, `--check-run`).

## Analysis Tiers

`m3tal-review` provides two distinct analysis tiers:

1. **Pattern & Inventory Tier (Default)**:
   - Deterministic, heuristic, local analysis applied to diffs (`review`), working trees (`audit`),
     or patches (`diff`/`stdin`).
   - ~95 pattern/AST rules, slop detectors, dependency hygiene, and package-scoped taint rules
     (Go, plus intra-file JS/TS approximations).
   - Multi-language support (Go, JS/TS, Python, Java, Kotlin, C/C++, C#, Rust, Swift, PHP).
   - Fast execution designed for interactive pre-commit and CI diff gating.

2. **Go Semantic Analysis Tier (Opt-In via `--semantic`)**:
   - Deep, whole-program, typed SSA analysis powered by `go/packages` and class-hierarchy analysis.
   - Six deterministic semantic engines: `flow` (interprocedural data-flow), `statemachine` (`statemachine/1`
     contracts), `typestate` (`typestate/1` single-use resource specs), `concurrency` (check-then-act,
     mutex lock-order deadlocks, unprotected field access), `authproto` (`authproto/1` cryptographic/nonce
     contracts), and `protocol` (`protocol/1` multi-version matrix comparison).
   - Only runs when explicitly requested via `--semantic` or user config `semantic.enabled`. A standard review
     without `--semantic` does not invoke these engines.
   - For architecture and contract specifications, see [`docs/semantic-pipeline.md`](semantic-pipeline.md),
     [`docs/statemachine-contracts.md`](statemachine-contracts.md), [`docs/typestate.md`](typestate.md),
     [`docs/concurrency.md`](concurrency.md), [`docs/protocol-contracts.md`](protocol-contracts.md),
     and [`docs/authproto-contracts.md`](authproto-contracts.md).

## What it is NOT

- **Not an absolute security proof.** Findings are pattern matches, heuristics, or bounded model checks—not
  formal verification of exploitability. A finding indicates high-risk code requiring human review; the
  absence of findings within bounded limits does not guarantee absolute security.
- **Tier-Specific Data-Flow & Type Resolution Boundaries:**
  - *Pattern Tier*: Has no cross-file or interprocedural data-flow, no type resolution beyond Go's stdlib AST,
    and no vulnerability database. The `request-taint` rule tracks request sources through assignments and
    intra-package call edges (bounded fixpoint); it does not follow values across packages, through interfaces,
    reflection, or goroutine boundaries. Tainted identifiers passed through recognized sanitizer/validator calls
    (`filepath.Base`, `filepath.Rel`, `html.EscapeString`, `strconv` parsers, `sanitize*`/`validate*`/`verify*`
    wrappers) are treated as guarded heuristics, not mathematical proofs.
  - *Semantic Tier (Go only)*: Evaluates typed whole-program SSA and interprocedural callgraphs, but operates
    under explicit bounded exploration budgets (`--semantic-depth standard|deep`, step/trace/origin limits,
    and `--semantic-timeout`). Dynamic calls that cannot be resolved via class-hierarchy analysis (e.g. arbitrary
    reflection or unmodeled interfaces) are recorded as diagnostics rather than soundly explored.
- **Language Coverage Disparity:**
  - Semantic whole-program analysis is currently implemented exclusively for **Go** (`internal/semantic/golang`).
    Other languages (JavaScript/TypeScript, Python, C/C++, etc.) do not gain semantic whole-program coverage and
    are analyzed exclusively via pattern/structural AST heuristics.
- **Bounded Completeness & Degraded Results:**
  - In semantic runs, when an analyzer exhausts its step or origin budget, its check status is marked as `warning`
    (`analysis truncated by budget`) and the aggregate analysis status is set to `degraded`. If an analyzer
    times out or fails to load, it is reported as `failed`. Downstream CI pipelines must not treat
    degraded/truncated runs as complete proof of compliance.
- **Not exhaustive.** Masked-mode rules cannot see inside string literals; several detectors therefore only
  fire on code-shaped signals. Obfuscated, dynamically constructed, or semantically disguised issues will be
  missed.
- **Fixture awareness is path-based.** Files under `tests/`, `test/`,
  `testdata/`, or `fixtures/` segments (and `*_test.*` names) are excluded
  from credential, entropy, secret-token, and file-permission rules because
  fixtures legitimately embed token-shaped and credential-shaped values.
  Test fixtures containing *real* leaked secrets will therefore be missed —
  PEM private-key blocks are the exception and still flag everywhere.
- **Workflow injection detection is syntax-scoped.** `actions-script-injection`
  only fires inside `run:`/`script:` executable contexts (including
  block-scalar bodies); `${{ github.event.* }}` in structural keys (`ref:`,
  `with:` inputs, `if:`, `env:`) is data, not shell, and is not flagged.
  Complex YAML (anchors, multi-document files, unusual indentation) may
  confuse the block tracker.
- **Credential classification is heuristic.** Google `AIza...` API keys are
  reported at medium because they are public-by-design in many first-party
  clients; genuinely private Google Cloud keys committed to source will be
  under-prioritized. URL-valued constants are never treated as credentials.

## Untrusted-input handling

Reviewed repositories are treated as hostile:

- All file reads go through path-safety checks (`filepath.IsLocal`); symlinks
  in policy/ignore/baseline/report paths are rejected.
- Diff size is capped (`--max-diff-size`, default 64 MiB); audit walks are
  bounded by `--max-files`/`--max-bytes`.
- Policy, ignore, and baseline files are size-capped JSON/glob inputs; invalid
  entries produce `review-policy-config-error` findings rather than aborts.
- Each rule runs under panic recovery and a per-rule timeout
  (`M3TAL_RULE_TIMEOUT`, default 2m); a crashing rule yields a confidence
  finding instead of terminating the review.
- Subprocess calls disable fsmonitor and cap output; no shell interpolation of
  repo-controlled data.

## Residual risks

- **False positives** are expected on a heuristic tool — use
  `m3tal-review: ignore <rule>` comments, `.m3tal-review-ignore`, policy
  `rules`/`paths` overrides, or `--skip` to tune.
- **False negatives** are the norm for anything requiring semantic analysis:
  taint tracking, auth-boundary reasoning, crypto misuse that is syntactically
  valid, business-logic flaws.
- **Secret detection** covers known token formats and filenames; novel secret
  shapes, encoded secrets, and secrets split across files will be missed.
  Rotate anything a scanner flags — and assume anything it doesn't flag may
  still be sensitive.
- `raw`-mode rules match inside comments and strings; they can fire on
  documentation examples.

## Severity rubric

Findings are calibrated so severity reflects practical exploitability, not
mere pattern presence:

- **critical** — committed live credential or key material.
- **high** — issues reachable from untrusted input with serious impact:
  injection, traversal to privileged operations, auth bypass, RCE-adjacent
  exec, wildcard permission defaults.
- **medium** — supply-chain and defense-in-depth concerns: unpinned actions,
  missing server timeouts, permissive CORS/WebSocket origins, credential
  propagation to subprocesses, plaintext secret storage.
- **low** — hygiene and informational: debug leftovers, log injection,
  timing-unsafe comparisons (impractical remotely), analyzer limitations.

Severity is a prioritization hint, not a verdict; always verify reachability
and authentication requirements before treating a finding as an incident.

## Recommended usage

1. Run `m3tal-review review` on staged changes before committing.
2. Use `--profile security` for security-focused passes, `--profile slop`
   for cleanup passes.
3. Maintain `.m3tal-review-policy.json` for repo-specific risk paths and
   per-rule/per-path tuning.
4. Use `--baseline`/`--write-baseline` to track findings across runs.
5. For high-assurance needs, complement with `gosec`, `eslint`, dependency
   scanning (`osv-scanner`), and secrets scanning (`gitleaks`) via
   `--with-tools`.
