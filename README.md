# m3tal-review

`m3tal-review` is a deterministic, local code-review CLI tool for the m3tal app ecosystem. It helps review code for maintainability (slop) and security issues.

It provides actionable findings, records review trails (history), and supports a manual fix-and-re-review workflow (automated repair tracking is not currently supported).

## Features

- **Review Engine**: `review` checks staged Git changes; `audit` checks the complete working-tree change set.
- **Remediation Guidance**: Every finding provides actionable steps to fix the issue.
- **Slop Detector**: For Go files, parses the exact staged file contents into an AST (`go/parser` and `go/ast`) to analyze added lines, detecting redundant boolean comparisons (`== true`), empty blocks (ignoring `interface{}`), excessive nesting depth (4+ levels), `else` after terminating statements, boolean-literal if/else returns, unreachable code, discarded call results, and oversized functions. JavaScript/TypeScript files use a deterministic syntax scanner for control-flow nesting, boolean comparisons, non-strict equality, and flow issues; Python files use indentation-aware control-flow analysis. Java, Kotlin, C/C++, C#, Rust, Swift, and PHP use language-configured structural scanners. Comments and string literals are excluded from these checks.
- **Staged-Only Semantics**: `review` accurately inspects staged content from the Git index (`git show :<file>`). Working-tree modifications that have not been staged are ignored. Deleted files are classified and handled without invoking AST analysis or generating false errors.
- **Working-Tree Audit**: `audit` checks tracked files present in the working tree, including unchanged files, plus non-ignored untracked files. Use `audit --include-ignored` to include ignored files such as `.env`. The scan defaults to 10,000 files and 128 MiB; files beyond either limit are reported as unanalyzed and make the run incomplete. Binary files, submodules, unreadable files, external symlinks, and common source languages without an analyzer are also reported as unanalyzed. The audit skips Git metadata and generated `.m3tal-review` data, and does not stage files or change the Git index.
- **Analysis Error Reporting**: Syntax errors in staged Go code or git index retrieval errors produce distinct high-severity findings (`code-slop-analysis-error`), ensuring that analysis failures cannot result in a passing review.
- **Security Checks**: Heuristic checks detect likely hardcoded credentials and exposed secrets (private key blocks, cloud/SCM/API tokens), committed secret files (.env, keys, credentials), world-writable file permissions, disabled TLS verification, risky shell APIs, request-controlled file paths and URLs (SSRF, command injection, open redirect), template injection, prototype pollution, unsafe archive extraction, XXE-prone XML parsing, weak cryptography and non-cryptographic randomness, ECB/static-IV cipher use, timing-unsafe secret comparisons, JWT `alg:none` and hardcoded session secrets, cookies without flags, credentials in web storage, missing postMessage origin checks, additional XSS sinks, CORS wildcard origins, unsafe deserialization, dynamic code evaluation, DOM-based XSS sinks, and string-built SQL/LDAP/XPath queries. Supply-chain checks flag unpinned GitHub Actions, `pull_request_target`, `${{ }}` script injection, curl|sh pipelines, unpinned images, CI secret exposure, privileged containers, and remote `ADD`/`git clone` in Dockerfiles. These checks are not a general security review: they do not perform data-flow analysis, framework-specific analysis, or complete parsing of every supported language. A passing run means only that the configured checks found no findings; it does not establish that the code is secure.
- **Confidence Profile**: `review --profile full` and `audit --profile full` also run `gofmt`, `go vet`, and `go test ./...`, with a five-minute timeout per command. This runs the repository's tests, so use it when you want code execution as part of review. `fast` remains the default.
- **Optional Local Scanners**: `--with-tools` runs installed `gitleaks`, `gosec`, and `osv-scanner` binaries using fixed command arguments and five-minute timeouts. Missing tools and execution failures are reported as incomplete checks. Gitleaks report output is redacted and only finding metadata is saved. OSV Scanner may need its local vulnerability database or network access, depending on its configuration. No scanner is invoked unless requested.
- **Code Quality**: Identifies `TODO`/`FIXME`/`XXX` comments and Markdown task headings, plus likely debug output in source files. String literals and non-source artifacts are excluded.
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

### Detector Rules

All findings come from deterministic heuristics; see `m3tal-review list-rules` for the live catalog and `m3tal-review explain <rule>` for per-rule detail.

**Core review & policy**

| Rule | Detects |
| --- | --- |
| `todo-marker` | TODO/FIXME/XXX markers in comments and Markdown task headings. |
| `debug-leftover` | Likely debug output: fmt.Print*, console.log, println, debugger, breakpoint, etc. |
| `review-risk` | Changed paths matching configured high-risk globs in .m3tal-review-policy.json. |
| `review-policy` | Policy violations: forbidden paths and missing coupled changes. |
| `code-slop` | Code-quality heuristics: redundant boolean comparisons, empty blocks, deep nesting, else-after-return, unre... |

**Secrets, credentials & crypto**

| Rule | Detects |
| --- | --- |
| `hardcoded-credential` | Credential-looking name/value assignments in source. |
| `exposed-secret` | High-confidence secret formats: PEM private keys and provider tokens (AWS, GitHub, GitLab, Slack, OpenAI, S... |
| `secret-file` | Committed files that look like secret material by name. |
| `secret-material` | Credential material in source: URLs with passwords, cloud keys, tokens. |
| `hardcoded-session-secret` | Session/JWT secrets hardcoded in source. |
| `jwt-misuse` | JWT 'none' algorithm or disabled signature verification. |
| `weak-cryptography` | MD5/SHA-1/DES/RC4 for security purposes; math/rand/random/Math.random for token-like values. |
| `weak-crypto-params` | ECB mode, static IVs, weak hashes, deprecated ciphers. |
| `timing-unsafe-compare` | Secret comparisons using ==/=== instead of constant-time functions. |
| `insecure-randomness` | Non-CSPRNG randomness for security-sensitive values. |
| `insecure-permissions` | World-readable/writable permissions on sensitive files. |
| `weak-encoding-crypto` | Base64/hex used where encryption may be intended. |
| `terraform-secret` | Literal credentials in .tf files. |
| `k8s-committed-secret` | Kubernetes Secret manifests committed to the repo. |

**Injection & code execution**

| Rule | Detects |
| --- | --- |
| `path-traversal` | File APIs fed by request input or os.Args without sanitization. |
| `sql-injection` | String-built SQL queries via fmt.Sprintf/concat/f-strings/template literals. |
| `ssrf` | Server-side request forgery: HTTP clients fetching request-controlled URLs. |
| `command-injection` | Shell/process execution built from request or interpolated data. |
| `open-redirect` | Redirect targets derived from request parameters. |
| `template-injection` | Templates rendered from user-controlled names or content. |
| `prototype-pollution` | Object merges/assignments with user-controlled keys; __proto__ access. |
| `archive-extraction` | Archive extraction without member path validation (zip-slip). |
| `xxe` | XML parsing APIs without entity-expansion protection. |
| `injection-other` | LDAP/XPath/header/mass-assignment injection variants. |
| `nosql-injection` | MongoDB operators or queries built from request data. |
| `graphql-injection` | GraphQL queries interpolated with user input. |
| `email-header-injection` | Email/SMTP headers or commands built from request data. |
| `spreadsheet-formula-injection` | CSV exports with request-controlled cells (=,+,-,@ formulas). |
| `dangerous-eval` | eval/exec/new Function/string setTimeout/assert-style dynamic execution. |
| `dynamic-code-loading` | Dynamic module/code loading from user-controlled names. |
| `unsafe-deserialization` | pickle/marshal/yaml.load/unserialize/node-serialize of untrusted data. |
| `deserialization-gadgets` | Polymorphic/unsafe deserialization gadget chains. |
| `unsafe-code` | unsafe/cgo/syscall/native-interface usage needing review. |
| `rust-unsafe` | unsafe blocks in Rust code. |
| `unsafe-c-functions` | Unbounded C library functions (gets/strcpy/sprintf). |

**Web & client-side**

| Rule | Detects |
| --- | --- |
| `cross-site-scripting` | innerHTML/outerHTML/document.write/dangerouslySetInnerHTML and template bindings that render raw HTML. |
| `xss-extra-sinks` | Additional HTML injection sinks incl. html/template typed strings. |
| `postmessage-origin` | postMessage without origin validation or with '*' target. |
| `web-storage-secrets` | Tokens stored in localStorage/sessionStorage (XSS-exfiltratable). |
| `cookie-flags` | Session cookies missing Secure/HttpOnly/SameSite; remember-me policy. |
| `cors-misconfig` | Wildcard CORS origin combined with credentials. |
| `cleartext-websocket` | ws:// cleartext WebSocket URLs. |
| `insecure-protocol` | Cleartext protocols: ftp/telnet/gopher/dict URLs. |
| `js-common-mistakes` | for...in prototype iteration, parseInt without radix. |

**Transport, availability & logging**

| Rule | Detects |
| --- | --- |
| `insecure-tls-verification` | TLS certificate verification disabled (InsecureSkipVerify, VERIFY_NONE, NODE_TLS_REJECT_UNAUTHORIZED=0). |
| `tls-verification` | TLS verification disabled or deprecated protocol versions. |
| `server-timeouts` | HTTP servers/clients without timeout configuration. |
| `client-timeouts` | HTTP clients without Timeout configured. |
| `missing-timeout` | Outbound calls without explicit timeout (requests, TLS server). |
| `unbounded-read` | Unbounded io.ReadAll on potentially large input. |
| `bind-all-interfaces` | Servers bound to all interfaces. |
| `env-passthrough` | Full environment passed to subprocesses. |
| `log-injection` | User-controlled data written to logs (log forging). |
| `sensitive-data-logging` | Tokens/secrets/passwords written to logs. |

**Supply chain, CI & infrastructure**

| Rule | Detects |
| --- | --- |
| `unpinned-action` | GitHub Actions pinned to mutable refs instead of SHAs. |
| `pull-request-target` | pull_request_target trigger risks running untrusted code privileged. |
| `actions-script-injection` | GitHub context interpolated into run: blocks. |
| `pipe-to-shell` | curl|sh style install pipes and insecure curl flags. |
| `unpinned-image` | Container images not pinned to digests. |
| `ci-secret-exposure` | Secrets echoed or inherited in CI workflows. |
| `container-privilege` | Privileged containers, host namespaces, root user, hostPath. |
| `dockerfile-remote-add` | Remote ADD/git clone in Dockerfiles (non-reproducible). |
| `dockerfile-user` | Dockerfile runs as root. |
| `iac-exposure` | World-open CIDRs, public ACLs, wildcard IAM, unencrypted storage. |
| `script-file` | Committed executable scripts (.bat/.ps1/.vbs/etc). |

### Slop Analyzer Coverage

`internal/review/language/lang_checker.go` identifies source languages by file extension for rules that need language-specific behavior. The slop analyzer routes each file to its language-specific implementation. Findings are limited to added lines while each syntax-aware analyzer reads the full staged file (or working-tree file during `audit`) for context.

| Language | Analysis | Current checks |
| --- | --- | --- |
| Go | Go AST | Redundant boolean comparisons, empty control blocks, deep nesting, `else` after terminating statements, boolean-literal if/else returns, unreachable code, discarded call results (`_ = f()`), and oversized functions/parameter lists |
| JavaScript / JSX | Local structural scanner | Boolean comparisons, empty control blocks, deep nesting, non-strict equality (`==`/`!=`, excluding `== null`), `else` after terminating statements, unreachable code, log-only `catch` blocks, and long boolean chains; reports mismatched delimiters |
| TypeScript / TSX | Local structural scanner | JavaScript-compatible checks and mismatched delimiters |
| Python | Indentation-aware scanner | Boolean comparisons, deep nesting, pass-only suites, incomplete suite detection, mutable default arguments, `else`/`elif` after terminating statements, unreachable code, and long boolean chains |
| Java, Kotlin, C/C++, C#, Rust, Swift, PHP | Language-configured structural scanner | Boolean comparisons, empty control blocks, deep control-flow nesting, `else` after terminating statements, unreachable code, and long boolean chains; reports mismatched delimiters |

All languages also get file-level heuristics on added lines: lint suppressions without justification (`//nolint`, `eslint-disable`, `# noqa`, `# type: ignore`, `@ts-ignore`, `//noinspection`, `shellcheck disable`, and similar), runs of commented-out code, and duplicated blocks of four or more identical lines.

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

# Filter rules, gate on severity, review against a base ref, or emit CI formats
m3tal-review review --only code-slop,secret-file --skip debug-leftover
m3tal-review review --fail-on high
m3tal-review review --base origin/main
m3tal-review review --format sarif    # or: github (Actions annotations)

# List rules, explain one, or install a pre-commit hook
m3tal-review list-rules
m3tal-review explain code-slop
m3tal-review install-hook [--force]

# More workflow options
m3tal-review review --profile security|slop|ci
m3tal-review review --baseline known-findings.txt --write-baseline new-baseline.json
m3tal-review review --include "*.go" --exclude "*_test.go" --sort-by severity --max-findings 100
m3tal-review review --format json|junit|codeclimate
m3tal-review review --summary-only --max-diff-size 33554432
m3tal-review review --rule code-slop

# Review arbitrary diffs or check the environment
m3tal-review diff change.patch
cat change.diff | m3tal-review stdin
m3tal-review doctor
m3tal-review version --json
m3tal-review watch            # re-review whenever the staged diff changes
m3tal-review completions bash # or zsh / fish
m3tal-review audit --with-tools
```

`audit` also accepts `--only`, `--skip`, `--fail-on`, and `--format` like `review`. Policy files support per-path rule overrides via `"paths": {"<glob>": {"<rule>": {"enabled": false, "severity": "info"}}}`.

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

### Environment variables

- `M3TAL_RULE_TIMEOUT` — per-rule analysis timeout (Go duration, default `2m`)
- `M3TAL_DEBUG` — print per-rule timing and finding counts to stderr

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
