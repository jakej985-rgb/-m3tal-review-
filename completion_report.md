## M3TAL Review — PR #1 Final Hardening Completion Report

1. **Changes made**:
   - **Priority 1 (Lint vs Review Separation)**: Documented the architectural separation between staged-only diff review (`review`) and repository-wide Go formatting/vet checks (`lint`) in `README.md`.
   - **Priority 2 (Non-destructive History Recovery)**: Implemented `RecoverHistory(reportsDir, historyPath string)` in `internal/review/history_recovery.go`. Rebuilds `history.jsonl` non-destructively in a temporary file (`0644`), validates report RunIDs and timestamps, sorts chronologically, flushes and syncs, and atomically replaces `history.jsonl`. If no valid reports exist or an error occurs, the existing history file is strictly preserved.
   - **Priority 3 (Correct AST Control-Flow Nesting)**: Refined `SlopRule` AST analysis to count only real control-flow statements (`*ast.IfStmt`, `*ast.ForStmt`, `*ast.RangeStmt`, `*ast.SwitchStmt`, `*ast.TypeSwitchStmt`, `*ast.SelectStmt`) rather than every `*ast.BlockStmt`. Maintained nesting depth tracking using an explicit stack with `ast.Inspect`, isolated sibling control-flow statements from accumulating depth, and reset depth to 0 at function boundaries (`*ast.FuncDecl`, `*ast.FuncLit`).
   - **Priority 4 (Hardened Git Diff Path Handling)**: Upgraded `ParseDiff` in `internal/review/diff.go` to parse git diff headers containing spaces and C-style quotes/escapes across additions, modifications, deletions, and renames. Added `StagedFileStatuses` in `internal/git/repository.go` parsing NUL-delimited status tokens.
   - **Priority 5 (Handled Missing Commit Metadata)**: Updated `execute("review")` in `internal/cli/cli.go` to explicitly check errors from `git.CurrentCommitSHA`, emit a warning to `os.Stderr`, and record `CommitSHA = "unavailable"` in the report rather than failing or silently dropping the error.
   - **Priority 6 (Atomic Report Durability)**: Enforced explicit permissions (`0644`) on temporary report and history recovery files, added parent directory `Sync()` after atomic `os.Rename`, and guaranteed cleanup deferrals on failure.

2. **Bugs fixed**:
   - Fixed AST nesting counter falsely incrementing on bare blocks and function root blocks.
   - Fixed AST nesting depth leaking across multiple function declarations in the same file.
   - Fixed `recover-history` destructive overwrite risks by making recovery completely non-destructive and atomic.
   - Fixed diff parser failure when parsing paths containing spaces or quotes.
   - Fixed silent discard of `CurrentCommitSHA` error in `internal/cli/cli.go`.

3. **Tests added**:
   - `internal/review/history_recovery_test.go`:
     - `TestRecoverHistorySuccess`: Verifies recovery of multiple reports into chronologically ordered `history.jsonl`.
     - `TestRecoverHistoryCorruptReportFiles`: Verifies corrupt JSON, invalid RunIDs, and zero timestamps are skipped with warnings while valid reports are recovered.
     - `TestRecoverHistoryPreservesExistingOnNoValidReports`: Verifies existing `history.jsonl` remains unmodified when no valid reports are present.
     - `TestRecoverHistoryWriteFailure`: Verifies error reporting and preservation when history destination directory is unwritable.
     - `TestRecoverHistoryReplacementFailure`: Verifies error reporting and temp file cleanup when destination path cannot be replaced.
   - `internal/review/slop_rule_test.go`:
     - `TestSlopRuleControlFlowNesting4Levels`: Verifies 4 nested control-flow constructs trigger the excessive nesting finding.
     - `TestSlopRuleControlFlowNesting3Levels`: Verifies 3 nested control-flow constructs do not trigger the finding.
     - `TestSlopRuleControlFlowSequentialSiblingIfs`: Verifies sequential sibling `if` blocks do not accumulate depth.
     - `TestSlopRuleControlFlowNestedLoopsAndSwitches`: Verifies mixed loops, switches, and selects trigger at 4+ levels.
     - `TestSlopRuleControlFlowMultipleFunctions`: Verifies independent functions in the same file reset nesting depth to 0.
     - `TestSlopRuleRealRepoWithSpacesInFilename`: Verifies AST slop checking on real Git repositories with staged files whose paths contain spaces.
   - `internal/review/diff_test.go`:
     - `TestParseDiffWithSpacesInFilenames`: Verifies diff parsing for additions, deletions, and renames with spaces.
     - `TestParseDiffWithQuotesInFilenames`: Verifies diff parsing for git diff headers with quotes and escapes.
   - `internal/git/repository_test.go`:
     - `TestStagedFileStatuses`: Verifies `StagedFileStatuses` correctly parses additions, modifications, deletions, and renames with spaces.
   - `internal/cli/cli_test.go`:
     - `TestLintVsReviewSeparation`: Verifies `review` succeeds when staged changes are clean even if an unformatted unstaged file exists, while `lint` fails.
     - `TestReviewHandlesMissingCommitMetadataUnbornBranch`: Verifies `review` on unborn branches warns on stderr and saves report with `CommitSHA = "unavailable"`.

4. **Exact validation commands and results**:
   - `gofmt -w .`: Passed cleanly.
   - `go test ./...`: Passed (all packages green).
   - `go test -race ./...`: Passed with race detector enabled across all packages.
   - `go vet ./...`: Passed without warnings.
   - `git diff --check`: Passed cleanly with zero whitespace or formatting warnings.
   - `go build ./cmd/m3tal-review`: Succeeded, producing executable binary.

5. **Remaining limitations**:
   - Go AST analysis requires syntactically valid Go code; syntax errors are reported as high-severity `code-slop-analysis-error` findings so users fix compilation errors first.
   - Non-Go files fall back to deterministic regex heuristics for slop detection as they cannot be parsed into a Go AST.
