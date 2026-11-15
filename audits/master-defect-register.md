# M3TAL Review — Master Defect Register (Audit In Progress)

Date: 2026-11-14. HEAD audited: `cadf451`. Mode: audit only.
Status legend: **C** = confirmed by reproduction or direct code proof,
**S** = suspected (code-read evidence, not reproduced), **U** = unverified.

Repair-subsystem detail lives in `audits/repair-subsystem-audit.md`.

---

## Phase 1 implementation status — 2026-11-14 (in progress)

All Phase 1 repair findings implemented; `go test ./...` green, `go vet` clean on touched packages.

| ID | Status | Fix summary |
|----|--------|-------------|
| R1 | FIXED | Callback receives a copy; post-approval integrity re-check refuses mutated proposals (`engine.go`). Regression: `TestAuditApprovalCallbackMutation` now asserts rejection. |
| R2 | FIXED | `ApplyProposalToContent` requires `ProposedContent` to equal patch application; `OriginalContent==""` no longer wildcards. |
| R3 | FIXED | Newline-safe `splitLines`/hunk emit + `\ No newline` markers; applier enforces declared hunk counts; CRLF round-trips. Regression: `audit_patch_test.go`. |
| R4 | FIXED | World-writable fixer only rewrites mode literals inside permission-call argument spans (masked strings/comments); bool fixer segment-aware. |
| R5 | FIXED | Audit-append failures collected into `result.Error`/audit entry per approved policy (apply + durability error). |
| R6 | FIXED | Worktree overlay now covers untracked (incl. ignored), symlinks, type changes, deletions, modes — parity with copy mode. Regression: `audit_sandbox_test.go`. |
| R7 | FIXED | `ApplyProposalToFile` writes via temp file + rename, preserves existing mode, creates parents 0755. |
| R8 | FIXED | `result.Error` cleared on success path. |
| R9 | FIXED | `resolveFindingsForRepair` tracks staged-vs-worktree provenance; staged findings on files with unstaged changes are rejected (`repair_cmd.go`). |
| R10 | FIXED | `symlinkEscapesRoot` containment check (lexical + `EvalSymlinks`) applied in `copyDirectory` and `overlayPath`; `removeEscapingSymlinks` sweeps the worktree sandbox for committed links materialized by `git worktree add`. Escaping links are absent from both modes; contained links preserved. Regression: `TestAuditSandboxWorktreeVsCopy` (updated — previously asserted the insecure behavior). |
| R11 | FIXED | See table above — scoping via `ScopeToSandbox` interface + baseline-before-apply + self-invalidating WT source cache. Regression: `TestScopeRulesToDir*` + existing engine workflow tests. |

Note: S6 fully closed in Phase 2 — staged (`workingTree=false`) reads key the cache by `.git/index` mtime+size (gitdir-aware), and `sourceBlockCache` validates per-file stamps on hit.

## Phase 1 — Data integrity & repair safety

| ID | Sev | Status | Subsystem | Finding | Files |
|----|-----|--------|-----------|---------|-------|
| R1 | High | C | repair | ApprovalHandler receives live `*Proposal`; mutating `ProposedContent` writes unverified bytes to the working tree; audit records the unmutated patch. Repro: `TestAuditApprovalCallbackMutation`. | `internal/repair/engine.go:291,325`, `patch.go:42` |
| R2 | Med | C | repair | `ApplyProposalToContent` prefers `ProposedContent` over `Patch`; `OriginalContent==""` is a wildcard that ignores current disk content. | `internal/repair/patch.go:42-47` |
| R3 | Med | C | repair | Diff/patch not newline-safe: trailing-newline state unrepresentable, `\ No newline` marker never emitted, content→empty yields `"\n"`, CRLF normalized to LF. `ApplyPatchToContent` ignores declared hunk counts that `ValidatePatch` enforces — the two parsers disagree on validity. | `internal/repair/diff.go`, `patch.go`, `validator.go` |
| R4 | Med | C | repair | `WorldWritableFileModeFixer` rewrites octal literals in comments, string literals, and unrelated same-line expressions (no argument-position check). Same line-scoped-regex class suspected in `RedundantBoolFixer`, `DebugLeftoverFixer`. | `internal/repair/fixer.go:227-389` |
| R5 | Med | C | repair | All `AppendRepairAudit` errors discarded; approved repair applies with zero durable audit record and no surfaced error. | `internal/repair/engine.go` (7 sites), `audit.go` |
| R6 | Med | C | repair | Worktree sandbox omits untracked files and non-regular overlay entries (untracked symlinks, exec-bit changes); verification can pass/fail on incomplete tree. Copy mode includes them → mode-dependent results. | `internal/repair/sandbox.go:195-218` |
| R7 | Low-Med | C | repair | `ApplyProposalToFile` non-atomic (no temp+rename/fsync); new parent dirs always 0755; TOCTOU between path validation and write. | `internal/repair/patch.go:12-39` |
| R8 | Low | S | repair | `result.Error` retains earlier attempt's error on eventual success. | `engine.go:92,237` |
| R9 | Low | S | repair | Findings sourced from staged diff repaired against working tree (stale line numbers); sequential same-file findings reuse stale lines. | `cli/repair_cmd.go:224-238`, `engine.go:371` |
| R10 | Low | S→FIXED | repair | Copy-mode sandbox recreates repo symlinks escaping the repo; contained for proposal writes by path validation, but present for the sandbox test runner. | `sandbox.go` |
| R11 | High | C→FIXED | repair/review | `scopeRulesToDir` reflection silently no-ops for rules with unexported `ruleRuntime` state (all `patternRule`/`customRule`/`filenameRule`/etc. from `ExtraRules`) → sandbox verification read the **real repo's** staged/working-tree content via `readRuleSource`. Additionally `ruleSourceCache` (process-global, keyed root+file+wt) served pre-apply content to post-apply checks, and `VerifyRemediation` evaluated the baseline *after* the sandbox apply so `new_blocking_findings` was vacuous. Fixed via `ruleRuntime.ScopeToSandbox` + copy-based scoping (`engine.go`), `VerifyRemediationWithBaseline` (`attestation.go`), and mtime+size-keyed working-tree source cache (`rule_source.go`). | `engine.go`, `review/attestation.go`, `review/rule_source.go`, `review/pattern_rule.go` |
| G1 | Med | C | git | `BinaryFilesAgainst` uses non-`-z` numstat: binary renames report `old => new` as path; non-ASCII paths quoted. Inconsistent with `StagedBinaryFiles` (verified `-z` order empirically — that parser is correct). | `internal/git/repository.go:486-520` |
| G2 | Low | S→FIXED | git/review | `git diff` invocations didn't pass `--no-textconv`; repo-configured textconv drivers could execute during review. `diff --git` header parse broke on paths containing `" b/"` and on filenames starting with `b/`. Both fixed: `--no-textconv` on all content-diff commands; header parser now disambiguates unquoted paths via same-path matching and preserves the `b/` prefix (`repository.go`, `repair/sandbox.go`, `review/diff.go`). |
| D1 | Med | C | deps | `collectImportPaths` walks nested modules: imports inside a nested `go.mod` tree count toward the root module's unused-dependency analysis → root deps used only by nested modules are never flagged. | `internal/deps/module.go:282-330` |
| V1 | Low-Med | C | vulnscan | `maxVulnDeps`(300)/`maxVulnFindings`(200) truncation is silent — no finding/warning that the scan was partial. OSV result↔dep mapping assumes API returns results in query order (unverified assumption). | `internal/cli/vulnscan.go:164-166,279-283` |

## Phase 2 implementation status — 2026-11-14

| ID | Status | Fix summary |
|----|--------|-------------|
| E1 | FIXED | `unionCapped` iterates `sortedOrigins` (canonical Kind/Index/ID order) → deterministic truncation; `ret` now routes through `unionCapped` so return-origin sets honor `MaxOrigins` (`flow/engine.go`). |
| S6 | FIXED | `ruleSourceCache` WT keys include file mtime+size; staged keys include `.git/index` mtime+size (gitdir-aware). `sourceBlockCache` entries carry per-file stamps validated on hit — no re-parse on the hot path (`rule_source.go`, `diff_source.go`). |
| S1 | FIXED (protocol) | `protocol.EvaluateMatrix(ctx, …)` checks ctx per version pair; `runProtocol` propagates ctx → analyzer timeout now interrupts the O(V²) loop. Other engines already consulted ctx. Residual: `runOne` still abandons (not kills) non-cooperative goroutines — all current analyzers now cooperate. |
| S2 | FIXED | ctx threaded through `authproto.Analyze`/`Evaluate`/`checkSourceBindings`/`checkNonceSource`/`scanRandUsage` (per-contract, per-field, per-BFS-item checks). |
| S5 | FIXED | New opt-in `review.ContextualRule` (`CheckContext(ctx, diff)`); all 32 rule implementations instrumented with per-file/per-block `ctx.Err()` checks; `checkRuleSafely` delivers the per-rule timeout via `context.WithTimeout` — timeouts now actually stop work. `customRule` nested timeout merged with parent ctx. `Engine.RunContext` + `VerifyRemediation(ctx,…)` propagate caller cancellation (repair engine passes its ctx). |
| S3 | FIXED | Truncated analyzers render check status `"warning"` (was `"passed"`) in `semanticCheckResults`. |
| S4 | FIXED | `Loader` entries carry a `programStamp` fingerprint (*.go + go.mod/go.sum mtimes/sizes, sorted FNV-1a); cache hits revalidate and reload on change. `BuildFlags` added to `pipeline.Options`, `loadKey`, and both `golang.Load` call sites (E3). |
| S7 | FIXED | `MaxCustomRules = 256` enforced in `ValidateCustomRulesConfig`. |
| E2 | FIXED (via S1) | O(V²) matrix is now bounded by ctx/analyzer timeout; `EvaluateMatrix` returns partial result + `ctx.Err()` on cancel. No separate pair cap — documented as acceptable given the timeout bound. |
| E3 | FIXED | `pipeline.Options.BuildFlags` exposed and forwarded (see S4). |

New finding recorded during implementation:

| ID | Sev | Status | Subsystem | Finding | Files |
|----|-----|--------|-----------|---------|-------|
| R12 | Low-Med | C | cli | `analyzeWorkingTree` calls `tr.Check(combined)` directly on taint rules — bypasses `checkRuleSafely` entirely: no per-rule timeout and no panic recovery (a panicking/hung taint rule crashes or stalls the working-tree review path). | `internal/cli/cli.go:1308` |

## Phase 2 — Semantic correctness

| ID | Sev | Status | Subsystem | Finding | Files |
|----|-----|--------|-----------|---------|-------|
| S1 | Med | C | pipeline | `runProtocol` ignores ctx (`EvaluateMatrix` has no ctx param): per-analyzer timeout cannot interrupt it; timed-out analyzer goroutine keeps running. `runOne` timeout/cancel never kills `def.Run` goroutine for any analyzer that ignores ctx — confirmed leak in `pipeline.go:454-490`. | `pipeline/analyzers.go:156-180`, `pipeline.go:454-490` |
| S2 | Med | C | pipeline | `authproto.Analyze`/`Evaluate`/`checkSourceBindings` accept ctx but never consult it — cancellation cannot interrupt authproto analysis (bounded only by MaxSourceDepth/Functions). | `internal/analysis/authproto/analyze.go:70`, `source.go:26-80` |
| S5 | Med | C | review engine | `checkRuleSafely` timeout returns a finding but the rule goroutine is never cancelled (no ctx in `Rule.Check`); hung rule leaks goroutine per run — accumulates in watch mode. Same leak class in `customRule.Check` (`custom_rules.go:437-470`) and pipeline `runOne` (S1). | `internal/review/engine.go:84-114` |
| S3 | Low-Med | C | pipeline/CLI | Truncated analyzer renders as check status `"passed"` with a note; overall section degrades only via `res.Truncated`. Per-check status understates partial analysis. | `cli/semantic.go:214-235` |
| S4 | Low | S | pipeline | `Loader` caches programs for process lifetime with no auto-invalidation; CLI never reuses a Loader so impact is embedded/watch-style reuse only. Stale analysis if tree changes. | `pipeline/loader.go:12-17` |
| S6 | Low-Med | C | rule source | `ruleSourceCache` (process-global, keyed by path+wt flag only) never invalidates; `watch` mode reuses the process so staged/working-tree file contents go stale between iterations — rules analyze old bytes. | `internal/review/rule_source.go:14-44` |
| S7 | Low-Med | S | custom rules | No cap on rule count in `.m3tal-review-rules.{yaml,json}` (1 MiB file can hold thousands of rules); engine runs all rules concurrently → CPU/goroutine amplification from untrusted repo content. RE2 regex + per-rule timeout bound each rule but not the count. | `internal/review/custom_rules.go`, `engine.go` |
| E1 | Med | C | analysis/flow | `unionCapped` iterates `originSet` (a Go map) and stops at `MaxOrigins` — which origins are retained is nondeterministic run-to-run under budget pressure → identical inputs can yield different findings, contradicting documented determinism. `addPlaces` flags truncation but never drops (inconsistent with unionCapped). | `internal/analysis/flow/engine.go:316-355`, `types.go:137` |
| E2 | Low | S | analysis/protocol | `EvaluateMatrix` is O(V²) over contract-declared versions; bounded only by `maxContractsPerFamily=256` → up to ~32k contract comparisons with no time budget and no ctx — potential long stall on adversarial contract dirs. | `internal/analysis/protocol/matrix.go:179`, `pipeline/contracts.go:25` |
| E3 | Info | C | semantic frontend | `golang.Options.BuildFlags` exists but `pipeline.Options` never exposes it — build-tag-gated code is silently unanalyzed in semantic mode; also `loadKey` omits nothing relevant but `BuildFlags` is unreachable. | `pipeline/loader.go:28-35`, `golang.go:53-55` |

## Phase 3 implementation status — 2026-11-14

| ID | Status | Fix summary |
|----|--------|-------------|
| P1 | FIXED | `findingGroup.toFinding` merges `Metadata` across all members (first-writer wins, primary overrides conflicts) and back-fills `Snippet`/`Reachability`/`Signature` from earlier members when the promoted primary lacks them (`group.go`). Regression: `TestGroupFindingsPreservesMetadataOnSeverityPromotion`. |
| P2 | FIXED | `findingGroup.matches` now compares `BaseFindingKey` and same-line domain/signature against **every** group member, not just `g.primary` → transitive matches join one group. Ordering preserved (base-key check before same-analyzer guard). Regression: `TestGroupFindingsTransitiveMemberMatch`. |
| P3 | FIXED | `toFinding` defaults empty `Confidence` to `"low"` for uncorroborated heuristic/pattern matches; single-finding path goes through the same code. Regression: `TestGroupFindingsEmptyConfidenceDefaultsLow`. |
| P4 | FIXED | `runner.go` reordered: report built + `WriteReport` + history append happen **before** `--check-run`/`--pr-comment` integrations; external failure can no longer lose the durable local report. |
| P5 | FIXED | `parseReviewOptions` tracks `hasValue` (presence of `=`) separately from value emptiness — `--flag=` yields explicit empty value without consuming argv; `--check-run-sha=<sha>` equals form now works via the shared `next()`. Regression: `TestParseReviewOptionsEqualsForm`. |
| P6 | FIXED | Git helpers generalized (`UnstagedFiles`, binary/submodule/mode-only detection across staged/unstaged/base); CLI computes real file statuses per mode and applies unsupported-language/binary/submodule/mode-only unanalyzed-file checks uniformly for staged, `--unstaged`, and `--base`. |
| P7 | FIXED | `ApplyFindingFilters` severity override preserves `RawSeverity` and records `severity_override`/`severity_override_reason` metadata for provenance instead of silently diverging top-level vs evidence severities (`filter.go`). |
| P8 | FIXED | `attestation.go` comments/name clarified: `m3tal-attestation/v1` is an unsalted integrity digest over public fields — tamper-evident against accidents, **not** a cryptographic signature; docs/comments no longer imply otherwise. |
| P9 | FIXED | `ParseGoMod` now tracks `exclude (`/`retract (` blocks (contents skipped, `)` closes any open block) and rejects go.mod directive keywords (`require`/`replace`/`exclude`/`retract`/`module`/`go`/`toolchain`/`use`/`godebug`) as phantom requirement paths inside `require (` blocks (`deps/module.go`). Residual (documented, not fixed): test-only and build-tag-excluded imports still count as "used" — needs `go list`-grade analysis, out of scope. |
| R12 | FIXED | New exported `review.RunRuleSafely(rule, diff)` wraps `checkRuleSafely` (timeout + panic recovery); `analyzeWorkingTree` taint-rule calls route through it instead of bare `tr.Check` (`engine.go`, `cli.go`). |

## Phase 3 — Review & reporting reliability

| ID | Sev | Status | Subsystem | Finding | Files |
|----|-----|--------|-----------|---------|-------|
| P1 | Med | C | grouping | `findingGroup.toFinding` copies only the primary finding's `Metadata` map; secondary findings' metadata (e.g. `analysis_truncated`, `analysis_truncation_reasons`) is silently dropped when severity promotion changes the primary. Reproduced earlier (transcript). | `internal/review/group.go:265-311` |
| P2 | Low-Med | S | grouping | `matches` compares `BaseFindingKey` only against `g.primary`, not all group members — transitive matches (C matches member B but not primary A) split into separate groups → duplicate-ish findings. | `group.go:188` |
| P3 | Med | C | report | Pattern-tier findings never set `Confidence` (only tool/semantic adapters and group promotion do): 59/106 findings in the inspected report lacked confidence; 35 lacked evidence analyzer. Report schema supports the fields — producers don't fill them. | `internal/review/*_rule.go`, `group.go` |
| P4 | Med | C | CLI/runner | `--check-run`/`--pr-comment` integrations run BEFORE report+history persistence; an integration failure returns error and the review result is never saved. Local artifact should be written first (or integration failure downgraded to warning). | `internal/cli/runner.go:197-209,290-295` |
| P5 | Low | C | CLI | `--flag=` with empty value: `next()` treats empty `value` as absent and consumes the following argv element — `--only=` mis-parses. `--check-run-sha` doesn't support `=` form (inconsistent). | `internal/cli/review_options.go:59-72,124-129` |
| P6 | Low | C | CLI | `review --base`/`--unstaged` synthesize all statuses as `"M"` and skip the submodule/mode-change/unknown-language unanalyzed-file checks that the staged path performs → review gaps unreported in those modes. | `internal/cli/cli.go:307-389` |
| P7 | Low | S | report | Policy severity overrides in `ApplyFindingFilters` mutate `f.Severity` post-grouping; `Evidence` entries and group-computed severity can diverge from the overridden value. | `internal/review/filter.go:56-63` |
| P8 | Info | C | attestation | "Signature" is unsalted SHA-256 over public fields — tamper-evident against accidents only, not adversarial modification (no key). Naming/docs should not imply cryptographic integrity. | `internal/review/attestation.go:74-120` |
| P9 | Low | S | deps | go.mod parser treats any two-token line inside `require (` as a requirement; `exclude`/`replace` semantics not modeled for vuln/deps accuracy; test-only and build-tag-excluded imports count as "used". | `internal/deps/module.go` |

## Phase 4 implementation status — 2026-11-14

| ID | Status | Fix summary |
|----|--------|-------------|
| O1 | FIXED | `commandWatch` uses `signal.NotifyContext` — SIGINT/SIGTERM cancels the context passed to `Engine.RunContext`, interrupting in-flight reviews; transient `git.StagedDiff` errors log to stderr and continue instead of killing watch; `lastHash` resets on empty diff so re-staged identical content re-reports (`watch.go`). |
| O2 | FIXED | Plugin stdout/stderr now use a 1 MiB `cappedBuffer` (same contract as `cli/exec.go`) — unbounded plugin output can no longer exhaust memory (`plugin/discovery.go`). |
| O3 | FIXED | `RunPlugins` receives `cfg.Context` (default `Background`) instead of hardcoded `context.Background()` (`runner.go`). Residual: no CLI call site populates `RunnerConfig.Context` yet — cancellation currently reaches plugins only via per-plugin timeouts; field is now wired for when callers supply it. |
| O4 | ACCEPTED | Missing/incompatible `--with-tools` scanner still yields a HIGH finding — explicit opt-in should fail loudly on missing coverage. Documented as intended strictness, not a defect. |
| O5 | DOCUMENTED | `ensureReviewStorageSafe` already runs immediately before report/history writes and writers are atomic temp+rename+fsync; residual is a sub-millisecond symlink-swap window requiring local write access to the repo dir — closing it needs `openat2`/`O_NOFOLLOW` machinery deemed disproportionate for the threat model. |
| O6 | DOCUMENTED | Audit cache keyed by rule-set + schema `"15"`; rule-behavior changes without a schema bump can serve stale findings (documented trade-off). Cache file is user-owned JSON — local-write injection is within the user's own trust boundary. |
| O7 | DOCUMENTED | Repo config influencing its own review coverage is expected plugin/config behavior. |
| O8 | DOCUMENTED | Plugin hash→exec TOCTOU requires local write access to the plugin dir within a nanosecond-scale window; accepted residual. |
| O9 | VERIFIED | Plugin trust boundary confirmed correct (see register entry). |
| G1 | FIXED | `BinaryFilesAgainst` now delegates to `ParseBinaryFilesFromNumstat` — `-z` rename records report the new path and malformed output errors instead of being silently skipped (`git/repository.go`). |
| G2 | FIXED | `--no-textconv` added to `StagedDiff`, `UnstagedDiff`, `WorkingTreeDiffAgainst`, and the repair sandbox diff — git config textconv filters can no longer rewrite binary content into misleading textual diffs (`git/repository.go`, `repair/sandbox.go`). |
| D1 | FIXED | `collectImportPaths` treats a directory containing its own `go.mod` as a module boundary (SkipDir) — imports inside nested modules no longer satisfy root requirements. `check.go` file counting updated: each module's `TotalGoFiles` covers only its own sources (no double-count, no loss). Regression: `TestAnalyzeGoModulesNestedModuleDoesNotMaskUnused`. |
| V1 | FIXED | Vuln-scan truncation is now surfaced: `collectDependencies` returns a dropped-dep count → `runVulnScan` emits a `vuln-scan-truncated` low finding; the `maxVulnFindings` cap in `queryOSV` emits the same finding instead of silently returning (`vulnscan.go`). |

## Phase 4 — Operational reliability

| ID | Sev | Status | Subsystem | Finding | Files |
|----|-----|--------|-----------|---------|-------|
| O1 | Low-Med | C | watch | `commandWatch` returns on any transient `git.StagedDiff` error (e.g. index.lock); identical re-staged diff after unstaging prints nothing (lastHash not reset on empty diff); in-flight review can't be interrupted until rule timeouts elapse. | `internal/cli/watch.go:37-67` |
| O2 | Low-Med | C | plugins | Plugin stdout/stderr captured in unbounded `bytes.Buffer` — a plugin emitting unbounded output can exhaust memory (host `runCommand` caps at 1 MiB; plugin path does not). | `internal/plugin/discovery.go:82-84` |
| O3 | Low | S | runner | `RunPlugins` uses `context.Background()`, ignoring `cfg.Context` — caller cancellation doesn't reach plugins (they do have per-plugin timeouts). | `internal/cli/runner.go:160` |
| O4 | Low | C | tool scanners | Missing/incompatible `--with-tools` scanner yields HIGH severity "confidence" finding → fails the whole run. Intended strictness but brittle; consider downgrading to check-status only. | `internal/cli/tool_scanners.go:50-160` |
| O5 | Low | S | storage | `ensureReviewStorageSafe` validates once per command; `AppendRepairAudit`/`AppendHistory` don't re-verify (TOCTOU on `.m3tal-review` symlink swap). Report/history writers themselves are atomic+fsync'd — good. | `internal/cli/cli.go:1375`, `internal/review/audit.go` |
| O6 | Low | S | audit cache | Cache keyed by rule-name set + schema string `"15"`; rule behavior changes without a schema bump serve stale findings (documented trade-off). Cache file in user cache dir is unverified JSON → locally writable findings injection (low trust boundary). | `internal/cli/audit_cache.go` |
| O7 | Info | C | config | Repo `.m3tal-review-config.json` `language_overrides` and policy files can alter language detection/suppression for the reviewed repo — expected, but means repo content influences its own review coverage. | `internal/cli/config.go:208-243` |
| O8 | Low | S | plugins | TOCTOU between SHA-256 allowlist check and `exec` of plugin binary (symlink/file swap after hash). Narrow window; requires local write access to plugin dir. | `internal/plugin/discovery.go:136-150,238-240` |
| O9 | Info | C | plugins | Plugin trust boundary verified correct: repo plugins require `--allow-repo-plugins` AND SHA-256 allowlist; hash checked before `--manifest` probe so unlisted binaries are never executed. Matches README claim. | `internal/cli/runner.go:131-143`, `plugin/discovery.go` |

## Phase 5 implementation status — 2026-11-14

| Item | Status | Notes |
|------|--------|-------|
| DOC1–DOC4 | RESOLVED | All four doc-claim contradictions fixed by R5/R6/R10/E1/S5 (see Documentation reconciliation table). |
| R10 | FIXED (late) | Symlink-escape containment added during Phase 5 sweep: `symlinkEscapesRoot` in copy + worktree overlay, plus `removeEscapingSymlinks` for committed links materialized by `git worktree add`. Regression: updated `TestAuditSandboxWorktreeVsCopy`. |
| G2 (header half) | FIXED (late) | `parseGitDiffHeaderPaths` disambiguates `" b/"`-containing and `b/`-prefixed filenames; regression `TestParseDiffBinaryHeaderAmbiguousPaths`. |
| `go vet ./...` | PASS | Clean across all packages. |
| `go test ./...` | PASS | All packages green after every phase. |
| `go test -race ./...` | PASS | No data races detected (full suite + re-run on post-edit review/repair/git/deps). |

## Documentation reconciliation (claims vs implementation)

| ID | Status | Claim | Reality |
|----|--------|-------|---------|
| DOC1 | Resolved | README: repair provides "durable audit logging" | R5 fixed: audit-append failure applies the repair but returns an explicit durability error — failures can no longer pass silently. |
| DOC2 | Resolved | README: repair runs "inside an isolated sandbox" | R6 fixed (worktree overlay parity: untracked/ignored/symlinks/type changes); R10 fixed (escaping symlinks excluded from both sandbox modes, incl. committed links in worktrees). |
| DOC3 | Resolved | ARCHITECTURE.md: output "deterministic" | E1 fixed: `unionCapped` sorts origins canonically before truncation; return-origin sets honor `MaxOrigins`. |
| DOC4 | Resolved | ARCHITECTURE.md: hung rule "produces a finding rather than failing the run" | S5 fixed: all rules implement `CheckContext`; timeouts deliver cancellable contexts so hung work actually stops. Residual: a rule ignoring ctx entirely still leaks its goroutine (documented limitation of the opt-in interface). |
| DOC5 | Consistent | Plugin repo-trust gating, atomic report writes, history fsync, staged-content-from-index | Verified in code |

## Second-pass deep audit — 2026-11-14 (coverage-gap closure)

Focused re-audit of the areas the first pass marked partial/unverified.

| Area | Result |
|------|--------|
| `taint_rule.go` + `js_taint_rule.go` (1.6k lines) | VERIFIED — bounded fixpoint (4 passes), per-statement taint snapshots, func-segment isolation, guard-call stripping, ambiguous-name exclusion, ctx checks. Heuristic false-negative gaps exist (multi-declarator JS lines) but are documented approximations with capped confidence. |
| `maskNonCode`/`sourceBlocks`/`diff_source.go` | VERIFIED — stamp-validated caches, offset-preserving masks. |
| ~20 remaining `*_rule.go` files | VERIFIED pattern-level — all use `sourceBlocks` + `addedLines` gating + ctx; no panic/index/unbounded-loop red flags. |
| `slop/` analyzer (~4.5k lines) | VERIFIED — Go path uses `go/parser`+`go/ast`; JS/Python/C-like use deterministic scanners; brace balance via `scanner.Scanner`; preprocessor expansion bounded. |
| `statemachine`/`concurrency`/`typestate` internals | VERIFIED — explicit step/trace/access budgets with truncation flags, ctx checks, `SortFindings`+`AssignFindingIDs` canonical ordering. Map-iteration order in `lockOrderFindings` inner loop is normalized by the downstream total-order sort — cosmetic only. |
| `deps/license.go` | VERIFIED — heuristic substring classification (documented); module-cache path escaping correct; deterministic sorted output. |
| `internal/semantic` non-Go frontends | MOOT — only `golang` frontend exists. |

New finding fixed during this pass:

| ID | Sev | Status | Subsystem | Finding | Files |
|----|-----|--------|-----------|---------|-------|
| D2 | Low | S→FIXED | deps | `assessGoReachability` walked into nested module dirs — imports inside a nested module made the ROOT dependency appear Reachable (same masking class as D1). Fixed with the same `go.mod` boundary SkipDir; `TotalGoFiles`-style counting unaffected. Regression: `TestGoReachabilityNestedModuleDoesNotCount`. | `internal/deps/reachability.go` |

## Coverage map (what was actually inspected)

- **Deep (read + targeted tests):** `internal/repair` (all files), `internal/git/repository.go`, `internal/review/{engine,group,diff,finding_identity,filter,report,report_writer,history_writer,history_recovery,report_validator,attestation,severity,pattern_rule,rule_source,custom_rules,taint_rule,js_taint_rule,diff_source,credential_file_perm_rule}.go` + pattern-level verification of all remaining `*_rule.go`, `internal/analysis/pipeline` (all), `internal/analysis/{flow,concurrency,statemachine,typestate,protocol,authproto}` (entry points, budgets, determinism, ctx — engine internals reviewed for bounds/ordering), `internal/semantic/golang` (all), `internal/cli/{cli,runner,semantic,watch,repair_cmd,review_options,exec,tool_scanners,vulnscan,config,audit_cache,checkrun}.go`, `internal/plugin` (all), `internal/deps/{check,module,license,reachability}.go`, `internal/review/slop` (structure + representative files).
- **Partial:** `internal/cli/{formats,history_prune,history_show,baseline,check_deps,lint,suppressions_cmd,config_diff,policy_diff,prcomment,completions,commands_extra,progress}.go`, `internal/review` remaining rule-file bodies (pattern-verified, not line-audited), `internal/review/{language,model}`, `internal/review/slop` per-language rule bodies.
- **Not audited:** per-rule correctness of individual pattern rules beyond structural verification; docs line-by-line reconciliation beyond the DOC-series claims check.

## Policy decisions — APPROVED 2026-11-14

1. **R5 audit-persistence failure:** apply the repair, but return an explicit durability error and mark the outcome uncertain. Never silently lose the audit trail; never block the fix itself.
2. **R1 callback integrity:** pass an immutable copy of the Proposal to `ApprovalHandler` AND re-verify applied bytes against the verified proposal before writing. Defense in depth.
3. **R6 sandbox parity:** unify on copy-mode semantics — worktree overlay must include untracked files and handle symlinks/mode changes equivalently, so verification sees the same tree in both modes.
4. **S5/S1 timeout leaks:** thread `context.Context` through the `Rule.Check` interface and analyzer internals so timed-out workers can actually be cancelled (~50 rules affected; API change accepted).
5. **E1 determinism:** sort origins before capped union so truncation is deterministic.
6. **R9 staged-vs-worktree:** reject repair when the finding's source diff doesn't match the current working tree (default assumption — flag if disputed).

## Validation baseline — 2026-11-14

HEAD: cadf45194a93cc6a04ffe5b9f10f6a3323d83c28
Go: go1.23.2 linux/amd64

- `go build ./...`: PASS (exit 0)
- `go test ./...`: FAIL (exit 1), isolated to intentional audit reproduction tests in `internal/repair`
- `go test ./internal/repair -run '^TestAudit' -count=1 -v`:
  - Expected failures: trailing-newline round trips, content-to-empty, no-newline marker
  - Confirmed: callback mutation, worktree/copy divergence
  - Normal audit append/read: PASS
  - Malformed hunk count: validator rejects, applier accepts
- All other packages in `go test ./...`: PASS

No production changes were made during this validation.
`go test -race ./...` and `go vet ./...` were deferred at baseline; both completed during implementation — see Phase 5 status below.

**Audit-test policy:** keep `internal/repair/audit_{repro,patch,sandbox}_test.go` as regression evidence, but convert each expected-failure assertion into a regression assertion asserting the *fixed* behavior as its defect is resolved — the suite must end fully green, not permanently red.

## Prioritized fix phases (proposal — pending approval)

1. **Repair safety:** R1 (copy proposal / re-verify applied bytes), R5 (surface audit failures per decision #1), R2+R3 (single source of truth: apply patch, or verify ProposedContent==patch result; fix newline handling), R4 (argument-aware fixing), R6 (worktree overlay untracked files per decision #3), R7 (atomic write), R9 (per decision #6).
2. **Semantic correctness:** S1+S2 (thread ctx into protocol/authproto; bound leaked analyzer goroutines), S3 (status naming), S4 (invalidation policy), E1 (deterministic capped unions), E2 (protocol matrix budget), E3 (expose BuildFlags).
3. **Review/report reliability:** P1 (merge metadata), P3 (confidence/evidence for pattern findings), P4 (persist before integrations), P2 (transitive grouping), P5-P7, S6 (ruleSourceCache invalidation for watch), S7 (custom-rule count cap).
4. **Operational:** O1-O8, G1-G2, D1, V1.
5. **Docs/release:** DOC1-DOC4 reconciliation, regression tests per finding, full `go test -race ./...` + vet.

## Regression tests required per confirmed defect

- R1: callback mutates ProposedContent → applied bytes must equal verified content (or mutation rejected). Extend `audit_repro_test.go`.
- R3: round-trip tests for trailing-newline add/remove, empty↔content, CRLF; validator/applier agreement test on malformed hunk counts. Extend `audit_patch_test.go`.
- R5: AuditPath pointing at a directory → repair must surface the failure per decision #1.
- R6: worktree sandbox must contain untracked files (or documented divergence test).
- P1: grouped finding with heterogeneous metadata → merged finding retains all evidence/metadata.
- P4: failing check-run integration → report+history still persisted.
- S6: watch-mode second iteration sees updated file contents.
- E1: run flow analysis twice on budget-exceeding input → identical findings.
- S1/S2: cancel ctx mid-analysis → analyzers return promptly; no leaked goroutines (verify with goleak or runtime.NumGoroutine).
