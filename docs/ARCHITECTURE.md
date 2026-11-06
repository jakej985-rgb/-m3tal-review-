# Architecture

How `m3tal-review` is organized internally. For behavior guarantees and scope
limits, see [threat-model.md](threat-model.md); for false-positive tuning see
[fp-tuning.md](fp-tuning.md).

## Package layout

```
cmd/m3tal-review/main.go      # entry point; os.Exit(1) on any command error
internal/cli/                 # command dispatch, flags, GitHub integration,
                              # formats, hooks, scanners, config, watch
internal/git/                 # thin wrapper over the `git` CLI:
                              # staged/unstaged/base diffs, file lists,
                              # statuses, repository root, file contents
internal/review/              # review engine, rules, storage, history
internal/review/language/     # extension → language routing for analyzers
internal/review/slop/         # per-language code-quality analyzers
internal/review/model/        # shared finding model
```

`internal/cli` never contains detection logic; it gathers input (a diff, a
working-tree snapshot, or piped text), invokes `internal/review`, and renders
or persists the result. `internal/git` shells out to `git` with
`core.fsmonitor=false` and never stages or mutates the index.

## Command flow

`cli.Run` dispatches on argv (`review`, `audit`, `diff`, `stdin`, `lint`,
`history`, `show`, `recover-history`, `install-hook`, `completions`,
`check`, `doctor`, `watch`, `list-rules`, `explain`, `version`). The two
analysis commands share a pipeline:

1. **Source acquisition**
   - `review`: `git.StagedDiff` by default; `--unstaged` uses the working-tree
     diff; `--base <ref>` diffs against a ref. Staged file *contents* are read
     from the index (`git show :<file>`), so unstaged edits are invisible.
   - `audit`: walks the working tree (tracked + non-ignored untracked files),
     reads current contents, and is bounded by `--max-files`/`--max-bytes`.
   - `diff`/`stdin`: parse an arbitrary patch or streamed diff.
2. **Policy + ignore loading**: `.m3tal-review-policy.json`,
   `.m3tal-review-ignore`, and user config
   (`~/.config/m3tal-review/config.json`) are read from the local working
   tree and size-capped; malformed entries become `review-policy-config-error`
   findings instead of aborting.
3. **Rule execution**: all registered rules run concurrently
   (`Engine.Run`, internal/review/engine.go). Each rule executes under panic
   recovery and a per-rule timeout (`M3TAL_RULE_TIMEOUT`, default 2m); a
   crashing or hanging rule produces a `<rule>-error`/`<rule>-timeout`
   confidence finding rather than failing the run. Results are concatenated
   in registration order, keeping output deterministic.
4. **Post-processing**: `ApplyFindingFilters` applies inline suppressions,
   ignore globs, and policy overrides; `--only`/`--skip`/`--rule`,
   `--include`/`--exclude`, `--fail-on`, `--sort-by`, `--max-findings`, and
   `--baseline`/`--write-baseline` narrow or gate the result.
5. **Side effects**: the run writes `.m3tal-review/reports/<run-id>.json`
   (atomic tmp+fsync+rename), appends to `.m3tal-review/history.jsonl`
   (fsync before close), and optionally posts to GitHub (`--check-run`,
   `--pr-comment`) or invokes external scanners (`--with-tools`,
   `--vuln-scan`).

Exit status: 0 when the run passes within the `--fail-on` threshold; non-zero
when findings at/above the threshold exist or the run is incomplete.

## Rule engines

Rules implement a common interface (`internal/review/rule.go`) returning
`[]Finding`. They fall into a few families:

- **Line/diff pattern rules** (`pattern_rule.go`, `secret_rule.go`,
  `sqli_rule.go`, `xss_rule.go`, `traversal_rule.go`, `tls_rule.go`,
  `crypto_rule.go`, `deserialization_rule.go`, `eval_rule.go`,
  `permissions_rule.go`, `shell_rule.go`, `extra_rules.go`): heuristic regex
  and masked-mode matching over added lines / full file contents.
- **AST rules**: Go files are parsed with `go/parser`/`go/ast` for the slop
  analyzer and correctness checks (`internal/review/slop/go_correctness.go`).
- **Structural scanners**: non-Go languages use deterministic tokenizers that
  track delimiters and control flow — JS/TS (`javascript_slop.go`,
  `typescript_slop.go`), Python (`python_slop.go`, indentation-aware), and a
  language-configured brace scanner shared by Java, Kotlin, C/C++, C#, Rust,
  Swift, PHP (`brace_language_slop.go`, `c_slop.go`, `cpp_slop.go`,
  `csharp_slop.go`, `java_slop.go`, `kotlin_slop.go`, `rust_slop.go`,
  `swift_slop.go`, `php_slop.go`). These are not full parsers; see the
  coverage table in the README.
- **Policy/config rules** (`policy_rule.go`): evaluate
  `.m3tal-review-policy.json` globs → `review-risk`, `review-policy`,
  `review-policy-config-error`.
- **External scanners** (`internal/cli/tool_scanners.go`, `vulnscan.go`):
  optional `gitleaks`, `gosec`, `osv-scanner` binaries and the OSV HTTP API,
  only when explicitly requested.

`internal/review/language/lang_checker.go` maps file extensions to languages
so the slop router picks the right analyzer; common extensions without an
analyzer are reported as unanalyzed, which marks the run incomplete.

## Storage layout (`.m3tal-review/`)

Per repository root (gitignored in this repo; consumers should gitignore it):

```
.m3tal-review/
  history.jsonl          # append-only JSONL log of run summaries
  history.jsonl.lock     # advisory lock for appends
  reports/<run-id>.json  # full Report per run (16-hex-char run ID)
```

- **History entry**: `{run_id, timestamp, status, finding_count, summary}`
  plus optional `scope` (`"working-tree"` for audits). Status is one of
  `passed`, `failed`, `incomplete`.
- **Report** (`internal/review/report.go`): `run_id`, `timestamp`,
  `repository`, `branch`, `commit_sha`, `base_commit_sha`, `diff_hash`,
  `tool_version`, `profile`, `scope`, `reviewed_files`,
  `unanalyzed_files`, `passed`, `summary`, `findings[]`, `checks[]`,
  `finding_changes`.
- **Finding** (`internal/review/model/finding.go`): `rule`, `severity`
  (`low|medium|high`), `file`, `line`, `message`, `remediation`, plus
  `category` (`security|review|confidence|risk|drift`, assigned by
  `categoryForRule` in engine.go), `id`, and diff-change metadata.
- **Durability**: report writes are tmp-file + `fsync` + `os.Rename`;
  history appends `fsync` before close; directory sync is best-effort.
  `recover-history` rebuilds `history.jsonl` from valid reports
  non-destructively, resolving duplicate run IDs deterministically
  (canonical `<run-id>.json` filename wins, then newest timestamp).

> **Name collision warning:** M3tal-core's internal review workflow also uses
> a `.m3tal-review/` directory, but with different file names and JSON
> schemas. It is a separate feature owned by M3tal-core; this CLI's
> `history.jsonl`/`reports/` layout is unrelated to it. See
> [INTEGRATION.md](INTEGRATION.md#m3tal-core-internal-review-vs-m3tal-review-cli).

## Config and state outside the repo

- `~/.config/m3tal-review/config.json` — user defaults (`profile`,
  `fail_on`, `format`, `only`, `skip`); CLI flags override.
- `~/.cache/m3tal-review/` — incremental audit cache.
- `M3TAL_RULE_TIMEOUT`, `M3TAL_DEBUG` — environment tuning.
