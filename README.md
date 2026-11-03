# m3tal-review

`m3tal-review` is a deterministic, local code-review CLI tool for the m3tal app ecosystem. It helps review code for maintainability (slop) and security issues.

It provides actionable findings, records review trails (history), and supports a manual fix-and-re-review workflow (automated repair tracking is not currently supported).

## Features

- **Review Engine**: `review` checks staged Git changes; `audit` checks the complete working-tree change set.
- **Remediation Guidance**: Every finding provides actionable steps to fix the issue.
- **Slop Detector**: For Go files, parses the exact staged file contents into an AST (`go/parser` and `go/ast`) to analyze added lines, detecting redundant boolean comparisons (`== true`), empty blocks (ignoring `interface{}`), and excessive nesting depth (4+ levels). JavaScript/TypeScript files use a deterministic syntax scanner for control-flow nesting and boolean comparisons; Python files use indentation-aware control-flow analysis. Java, Kotlin, C/C++, C#, Rust, Swift, and PHP use language-configured structural scanners. Comments and string literals are excluded from these checks.
- **Staged-Only Semantics**: `review` accurately inspects staged content from the Git index (`git show :<file>`). Working-tree modifications that have not been staged are ignored. Deleted files are classified and handled without invoking AST analysis or generating false errors.
- **Working-Tree Audit**: `audit` checks all tracked files present in the working tree, including unchanged files, plus non-ignored untracked files. Its Go AST checks read the actual files from disk. It skips Git metadata, ignored untracked files, and generated `.m3tal-review` data. Binary files, submodules, unreadable files, and symlinks whose targets leave the repository are recorded as unanalyzed, and the report is marked incomplete. The audit does not stage files or change the Git index.
- **Analysis Error Reporting**: Syntax errors in staged Go code or git index retrieval errors produce distinct high-severity findings (`code-slop-analysis-error`), ensuring that analysis failures cannot result in a passing review.
- **Security Checks**: Detects hardcoded credentials, world-writable file permissions (0777), disabled TLS verification, and risky shell executions.
- **Code Quality**: Identifies leftover `TODO` markers and debug print statements in staged diffs.
- **Independent Repository Linting**: Dedicated `lint` command runs `gofmt` and `go vet` across the entire repository to enforce formatting and catch subtle bugs without interfering with staged-only diff reviews.
- **Review History**: Maintains a JSONL log of previous reviews with atomic writes and durable recovery.
- **Detailed Reports**: Saves full review results as JSON files.

### Slop Analyzer Coverage

`internal/review/language/lang_checker.go` identifies source languages by file extension for rules that need language-specific behavior. The slop analyzer routes each file to its language-specific implementation. Findings are limited to added lines while each syntax-aware analyzer reads the full staged file (or working-tree file during `audit`) for context.

| Language | Analysis | Current checks |
| --- | --- | --- |
| Go | Go AST | Redundant boolean comparisons, empty control blocks, and deep nesting |
| JavaScript / JSX | Local structural scanner | Boolean comparisons, empty control blocks, and deep nesting; reports mismatched delimiters |
| TypeScript / TSX | Local structural scanner | JavaScript-compatible checks and mismatched delimiters |
| Python | Indentation-aware scanner | Boolean comparisons, deep nesting, pass-only suites, and incomplete suite detection |
| Java, Kotlin, C/C++, C#, Rust, Swift, PHP | Language-configured structural scanner | Boolean comparisons, empty control blocks, deep control-flow nesting, and mismatched delimiters |

The non-Go structural scanners tokenize source and apply language-specific control-flow and boolean rules; they are not complete language parsers. C, C++, C#, and Swift conditional compilation scans one branch, so findings in alternate branches may be missed. Unsupported syntax can also be missed, so the analyzer coverage table reflects the checks currently implemented.

## Installation

Ensure you have Go 1.23+ installed.

```bash
go build -o m3tal-review ./cmd/m3tal-review
```

Move the binary to a directory in your `PATH` (e.g., `/usr/local/bin`).

## Usage

Run the CLI inside a Git repository.

### Check Status

View the current repository state, branch, and staged files:

```bash
m3tal-review check
```

### Run a Review

Review currently **staged** changes. This will generate a run ID, create a report, and log it to history.

```bash
m3tal-review review
```

### Audit the Working Tree

Analyze the complete working-tree snapshot, including unchanged tracked files, staged and unstaged edits, and non-ignored untracked files:

```bash
m3tal-review audit
```

The report and history entry record the `working-tree` scope. Audit reads current file contents, does not stage changes, and marks the run incomplete when any in-scope file cannot be analyzed.

If issues are found, the command will exit with a non-zero status and print the findings with their line numbers and remediation guidance.

To address findings:
1. Manually fix the issues in your code based on the remediation guidance.
2. Stage your changes (`git add`).
3. Run `m3tal-review review` again to verify the fixes.

### View History

List past reviews and their summaries:

```bash
m3tal-review history
```

### View a Specific Report

Retrieve the full details and findings of a past review using its Run ID:

```bash
m3tal-review show <run-id>
```

### Linting

Run standard Go formatting and vet checks across the repository:

```bash
m3tal-review lint
```

### Recover History

Rebuild the review history log (`history.jsonl`) non-destructively from valid report files:

```bash
m3tal-review recover-history
```

If multiple report files contain the same Run ID (e.g., from manual copies or backups), recovery deterministically selects the canonical `<run-id>.json` report (or newest timestamp if non-canonical), ensuring no duplicate entries are introduced.

## Storage & Durability

Review reports (`.m3tal-review/reports/<run-id>.json`) and review history (`.m3tal-review/history.jsonl`) use atomic and durable storage patterns:
- **Reports**: Reports are written to a temporary file (`0644`), synced via `fsync` (`file.Sync()`), and atomically moved into place using `os.Rename`. Parent directory syncing following rename is best-effort (failures are non-fatal warnings). On any write or sync failure prior to rename, temporary files are cleanly unlinked.
- **History Log**: Appends to `history.jsonl` are flushed and synced via `fsync` before closing.
- **Recovery Non-Destructiveness**: The `recover-history` command builds recovered history in a temporary file and atomically replaces `history.jsonl` only after all reports are validated and sorted. If no valid reports exist or an error occurs, the existing history file is completely preserved.
- **Durability Limitations**: File payloads are persisted via OS sync calls (`fsync`). Directory-level metadata syncing is best-effort and subject to host OS and filesystem capabilities.

## Interpreting Findings

Findings include:
- **Severity**: `low`, `medium`, or `high`.
- **File/Line**: Where the issue occurred.
- **Message**: A description of the problem.
- **Remediation**: Actionable advice on how to resolve the issue.

Example finding:
```
[high] main.go:42: Possible hardcoded credential assigned to password (hardcoded-credential)
  Remediation: Remove hardcoded credentials. Use environment variables or a secret management system.
```
