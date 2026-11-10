# m3tal-review — Threat Model & Limitations

## What this tool is

m3tal-review is a **deterministic, heuristic, local** code reviewer. It parses
diffs (staged, unstaged, `--base`, patch files, or stdin) and applies ~70
pattern/AST rules plus language-aware slop analyzers. It makes no network
calls except when explicitly asked (`--with-tools` scanners, `--check-run`).

## What it is NOT

- **Not a security analyzer.** Findings are pattern matches, AST heuristics,
  and limited intra-file taint tracking, not proof of vulnerability. A finding
  means "this looks risky — review it", not "this is exploitable".
- **Not a replacement for gosec, eslint, CodeQL, or a SAST pipeline.** It has
  no interprocedural or cross-file dataflow, no type resolution beyond Go's
  stdlib AST, and no vulnerability database. The `request-taint` rule tracks
  request sources through simple assignments within a single file only; it
  does not follow values across functions, packages, or goroutines.
- **Not exhaustive.** Masked-mode rules cannot see inside string literals;
  several detectors therefore only fire on code-shaped signals. Obfuscated,
  dynamically constructed, or semantically disguised issues will be missed.

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
