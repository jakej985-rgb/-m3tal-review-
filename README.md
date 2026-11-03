# m3tal-review

`m3tal-review` is a deterministic, local code-review CLI tool for the m3tal app ecosystem. It helps review code for maintainability (slop) and security issues.

It provides actionable findings, records review trails (history), and supports a manual fix-and-re-review workflow (automated repair tracking is not currently supported).

## Features

- **Review Engine**: `review` checks staged Git changes; `audit` checks the complete working-tree change set.
- **Remediation Guidance**: Every finding provides actionable steps to fix the issue.
- **Slop Detector**: For Go files, parses the exact staged file contents into an AST (`go/parser` and `go/ast`) to analyze added lines, detecting redundant boolean comparisons (`== true`), empty blocks (ignoring `interface{}`), and excessive nesting depth (4+ levels). JavaScript/TypeScript files use a deterministic syntax scanner for control-flow nesting and boolean comparisons; Python files use indentation-aware control-flow analysis. Java, Kotlin, C/C++, C#, Rust, Swift, and PHP use language-configured structural scanners. Comments and string literals are excluded from these checks.
- **Staged-Only Semantics**: `review` accurately inspects staged content from the Git index (`git show :<file>`). Working-tree modifications that have not been staged are ignored. Deleted files are classified and handled without invoking AST analysis or generating false errors.
- **Working-Tree Audit**: `audit` checks tracked files present in the working tree, including unchanged files, plus non-ignored untracked files. Use `audit --include-ignored` to include ignored files such as `.env`. The scan defaults to 10,000 files and 128 MiB; files beyond either limit are reported as unanalyzed and make the run incomplete. Binary files, submodules, unreadable files, external symlinks, and common source languages without an analyzer are also reported as unanalyzed. The audit skips Git metadata and generated `.m3tal-review` data, and does not stage files or change the Git index.
- **Analysis Error Reporting**: Syntax errors in staged Go code or git index retrieval errors produce distinct high-severity findings (`code-slop-analysis-error`), ensuring that analysis failures cannot result in a passing review.
- **Security Checks**: Heuristic checks detect likely hardcoded credentials, world-writable file permissions, disabled Go TLS verification, and selected risky shell APIs. These checks are not a general security review: they do not perform data-flow analysis, framework-specific analysis, or complete parsing of every supported language. A passing run means only that the configured checks found no findings; it does not establish that the code is secure.
- **Confidence Profile**: `review --profile full` and `audit --profile full` also run `gofmt`, `go vet`, and `go test ./...`, with a five-minute timeout per command. This runs the repository's tests, so use it when you want code execution as part of review. `fast` remains the default.
- **Optional Local Scanners**: `--with-tools` runs installed `gitleaks`, `gosec`, and `osv-scanner` binaries using fixed command arguments and five-minute timeouts. Missing tools and execution failures are reported as incomplete checks. Gitleaks report output is redacted and only finding metadata is saved. OSV Scanner may need its local vulnerability database or network access, depending on its configuration. No scanner is invoked unless requested.
- **Code Quality**: Identifies leftover `TODO` markers and debug print statements in staged diffs.
- **Independent Repository Linting**: Dedicated `lint` command runs `gofmt` and `go vet` across the entire repository to enforce formatting and catch subtle bugs without interfering with staged-only diff reviews.
- **Review History**: Maintains a JSONL log of previous reviews with atomic writes and durable recovery.
- **Detailed Reports**: Saves full review results as JSON files.

### Deterministic Review Categories

Findings are assigned to `security`, `review`, `confidence`, `risk`, or `drift` categories in JSON reports. Projects can configure deterministic risk and drift rules in a root `.m3tal-review-policy.json` file:

```json
{
  "risk_paths": ["internal/auth/**", "migrations/**"],
  "forbidden_paths": ["internal/legacy/**"],
  "require_together": [
    {"when_changed": "api/openapi.yaml", "also_change": ["docs/api/**"]}
  ]
}
```

`risk_paths` adds informational findings that do not fail a run. `forbidden_paths` and `require_together` produce actionable drift findings. Patterns use `/` separators, `*` for one path segment, and `**` for any number of segments. The policy is read from the local working tree, so a local policy can govern a staged review even before the policy file is staged.

### Slop Analyzer Coverage

`internal/review/language/lang_checker.go` identifies source languages by file extension for rules that need language-specific behavior. The slop analyzer routes each file to its language-specific implementation. Findings are limited to added lines while each syntax-aware analyzer reads the full staged file (or working-tree file during `audit`) for context.

| Language | Analysis | Current checks |
| --- | --- | --- |
| Go | Go AST | Redundant boolean comparisons, empty control blocks, and deep nesting |
| JavaScript / JSX | Local structural scanner | Boolean comparisons, empty control blocks, and deep nesting; reports mismatched delimiters |
| TypeScript / TSX | Local structural scanner | JavaScript-compatible checks and mismatched delimiters |
| Python | Indentation-aware scanner | Boolean comparisons, deep nesting, pass-only suites, and incomplete suite detection |
| Java, Kotlin, C/C++, C#, Rust, Swift, PHP | Language-configured structural scanner | Boolean comparisons, empty control blocks, deep control-flow nesting, and mismatched delimiters |

The non-Go structural scanners tokenize source and apply language-specific control-flow and boolean rules; they are not complete language parsers. C, C++, C#, and Swift conditional compilation scans one branch, so findings in alternate branches may be missed. Unsupported syntax can also be missed. Common source file extensions without an analyzer are listed as unanalyzed and make the run incomplete. Security checks remain heuristic and may miss issues beyond the patterns listed above.

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

Add local Go formatting, vet, and test checks:

```bash
m3tal-review review --profile full
```

### Audit the Working Tree

Analyze tracked files and non-ignored untracked files, including unchanged files and staged or unstaged edits:

```bash
m3tal-review audit
```

Include ignored files such as `.env`, or adjust the default scan budgets:

```bash
m3tal-review audit --include-ignored --max-files 20000 --max-bytes 536870912
```

Add the Go confidence checks to an audit with `--profile full`.

Run additional installed local security scanners explicitly:

```bash
m3tal-review review --with-tools
m3tal-review audit --with-tools
```

`--with-tools` uses any installed `gitleaks`, `gosec`, and `osv-scanner`; each unavailable scanner makes the requested scan incomplete. OSV Scanner may need network access to obtain vulnerability data.

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
