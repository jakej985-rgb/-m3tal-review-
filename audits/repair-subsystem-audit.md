# M3TAL Review — Repair Subsystem Audit

Date: 2026-11-14. Scope: `internal/repair`, `internal/cli/repair_cmd.go`.
Mode: audit only — reproduction tests live in `internal/repair/audit_*_test.go`.

## Confirmed defects

### R1 — Approval callback can substitute unverified content (HIGH)
`RepairEngine.RepairFinding` passes the live `*Proposal` (`finalProposal`) to
`ApprovalHandler` after sandbox verification, then applies that same pointer via
`ApplyProposalToFile`. `ApplyProposalToContent` prefers `ProposedContent`
verbatim whenever `OriginalContent` matches current disk content, and
`ValidatePatchBoundaries` never checks that `ProposedContent` equals the patch
result. A handler that mutates `prop.ProposedContent` (buggy or hostile) causes
unverified bytes to be written to the working tree; the audit entry still
records the unmutated `Patch`, so the durable trail diverges from reality.
Reproduced: `TestAuditApprovalCallbackMutation` — mutated content
`package pwned...` was written to disk; outcome `approved_and_applied`.
Files: `internal/repair/engine.go:291,325`, `internal/repair/patch.go:42-47`.
Fix direction: pass a copy or value to the handler; re-derive content from the
verified patch at apply time, or re-verify `ProposedContent == apply(Patch)`
immediately before writing; audit the actually-applied bytes.

### R2 — Patch and ProposedContent can diverge; patch is decorative (MEDIUM)
`NewProposal` regenerates `Patch` from contents at build time, so the engine
itself stays consistent — but `ApplyProposalToContent` ignores `Patch` whenever
`ProposedContent` is non-empty and `OriginalContent` matches (or is empty).
`OriginalContent == ""` acts as a wildcard: a proposal against an
originally-empty file overwrites whatever is currently on disk.
Reproduced earlier (transcript): patch said "different replacement",
`ProposedContent` said "intended replacement", disk got `ProposedContent`.
Files: `internal/repair/patch.go:42-47`.

### R3 — Patch parser/applier defects (MEDIUM)
`GenerateUnifiedDiff`/`splitLines` discard trailing-newline state; the
`\ No newline at end of file` marker is never emitted and is only partially
honored on apply (global `strings.Contains` heuristic). Confirmed by
`TestAuditPatchRoundTrip`:
- add/remove trailing newline: not representable, apply produces wrong result
- content → empty (`@@ -1,1 +1,0 @@`): yields `"\n"` instead of `""`
- CRLF input normalized to LF on apply (data corruption in fallback path)
`ValidatePatch` enforces declared hunk counts and hunk ordering;
`ApplyPatchToContent` ignores counts entirely and will apply patches
`ValidatePatch` rejects (`TestAuditPatchMalformed/hunk_count_mismatch`
applied with no error). The engine always validates first, so this is
defense-in-depth divergence today, but the two parsers disagree on validity.
Files: `internal/repair/diff.go:66-77`, `internal/repair/patch.go:50-162`,
`internal/repair/validator.go:104-226`.

### R4 — WorldWritableFileModeFixer false positives (MEDIUM)
`fixWorldWritableModeInLine` rewrites every octal/`os.ModePerm` literal on the
target line(s) whenever the line merely *contains* a mkdir/write-ish context —
no check that the literal is actually a permission argument. Reproduced
(transcript): `0777` inside comments, inside raw string literals, and an
unrelated `log.Println(0777)` on the same line all rewritten to `0644`.
Files: `internal/repair/fixer.go:227-264`. Similar line-scoped regex rewriting
exists in `RedundantBoolFixer` and `DebugLeftoverFixer` (comments/strings not
excluded) — suspected, same class.

### R5 — Repair audit persistence failures are silently ignored (MEDIUM)
All seven `AppendRepairAudit` call sites in `engine.go` discard the error
(`_ =`). Reproduced (transcript): `AuditPath` pointing at a directory still
produced `approved_and_applied` with `Error=<nil>` — an approved repair was
applied with zero durable record and no surfaced failure. The CLI's
`ensureReviewStorageSafe` catches symlink/path escapes upfront but not
write/permission/IO failures at append time.
Files: `internal/repair/engine.go` (all audit call sites),
`internal/repair/audit.go:48-82`.
Decision needed: should audit failure block apply, downgrade outcome, or at
minimum surface in `result.Error`/stderr?

### R6 — Worktree sandbox omits untracked files and non-regular overlay entries (MEDIUM)
`overlayWorkingTreeChanges` uses `git diff HEAD --name-only`, which excludes
untracked files entirely, and skips any non-regular file (symlinks, and
therefore symlink targets and exec-bit-only mode changes are not overlaid).
Reproduced: `TestAuditSandboxWorktreeVsCopy` — worktree sandbox contained the
modified tracked file but no `untracked.txt` and no untracked symlink, while
copy mode contains both. Consequence: `VerifyRemediation` in worktree mode
runs rules/tests against a tree missing untracked sources — findings can be
reported "fixed" (or tests fail) based on incomplete content. `PreferWorktree`
defaults false, so exposure is opt-in, but the CLI never sets it — engine API
users can enable it.
Files: `internal/repair/sandbox.go:195-218`.

### R7 — Non-atomic apply write; permission edge cases (LOW-MEDIUM)
`ApplyProposalToFile` writes via `os.WriteFile(targetPath, ..., 0644)` directly:
no temp-file+rename, no fsync — a crash mid-write leaves a truncated target.
Perm `0644` applies only at creation; existing modes are preserved (good), but
newly created parent dirs are always `0755` and a missing target file is
created `0644` regardless of repo conventions. TOCTOU: symlink/path validation
(`ValidateTargetFilePath`) and the subsequent `WriteFile` are separate steps.
Files: `internal/repair/patch.go:12-39`.

## Suspected / lower-confidence

- S1: `result.Error = lastErr` retains an earlier attempt's error even when a
  later attempt succeeds — `RepairResult.Error` can be non-nil on
  `approved_and_applied`. (`engine.go:92,237`)
- S2: `resolveFindingsForRepair` can source findings from the *staged* diff
  while the engine repairs *working-tree* content; finding line numbers may be
  stale relative to disk. (`cli/repair_cmd.go:224-238`)
- S3: Sequential `RepairFindings` on multiple findings in the same file: the
  second repair re-reads the file but reuses the original finding's line
  numbers — fixer may edit the wrong line; patch context matching may then
  fail verification. (`engine.go:371-383`)
- S4: Copy-mode sandbox recreates repo symlinks verbatim, including links
  escaping the repo (`link.txt -> /tmp/outside-secret.txt` reproduced). Target
  writes are still contained by `ValidateTargetFilePath` symlink resolution,
  but the sandbox test runner (`go test ./...`) executes with those links
  present. (`sandbox.go:156-162`)
- S5: `copyDirectory` has no size/count bounds — copying a repo with large
  artifacts (node_modules, build output) happens once per attempt per finding.
  Performance, not correctness.
- S6: `scopeRulesToDir` uses reflection to mutate unexported-struct fields
  `RepositoryRoot`/`WorkingTree` — silently no-ops for rules lacking those
  exact field names/types, so some rules may still read the real repo root
  during sandbox verification. Needs per-rule verification.

## Verified non-issues

- Path traversal (`../../etc/passwd`) rejected; symlink escapes in target path
  rejected by `ValidateTargetFilePath`.
- No auto-commit/push: `TestRepairWorkflowApprovedAndAppliedWithoutCommitOrPush`
  asserts HEAD unchanged.
- Dry-run performs no working-tree writes (sandbox + test runner still run;
  audit entry still appended — by design).
- Rejected/dry-run/failed outcomes leave working tree untouched (existing tests).
- `git worktree` cleanup (`remove --force` + `prune` + `RemoveAll`) works;
  fallback to copy mode on worktree failure verified by code path.
