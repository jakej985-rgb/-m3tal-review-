# m3tal-review

`m3tal-review` is a deterministic, local code-review CLI tool for the m3tal app ecosystem. It helps review code for maintainability (slop) and security issues.

It provides actionable findings, records review trails (history), and provides a constrained, isolated repair workflow with durable audit logging.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — package layout, command pipeline, rule engines, and `.m3tal-review/` storage.
- [`docs/INTEGRATION.md`](docs/INTEGRATION.md) — using m3tal-review across the M3tal ecosystem repos, hooks, and CI; disambiguates the `.m3tal-review/` directory from M3tal Core's separate internal review workflow.
- [`docs/RELEASE.md`](docs/RELEASE.md) — versioning, CI gates, and tagging a release.
- [`docs/threat-model.md`](docs/threat-model.md) — what the tool guarantees and what it explicitly does not.
- [`docs/fp-tuning.md`](docs/fp-tuning.md) — false-positive tuning and policy configuration.
- `completion_report.md` — historical release-gate report (superseded; kept for audit history).

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
- **External Analyzer Plugins**: `review` and `audit` can run external analyzer plugins discovered from `--plugin-dir <path>`, the `plugin_dir` key in `~/.config/m3tal-review/config.json`, or `~/.config/m3tal-review/plugins` by default. Plugins inside the reviewed repository (`.m3tal-review/plugins`) are treated as untrusted: they are never loaded unless you pass `--allow-repo-plugins` **and** list each executable's SHA-256 hash in `plugin_allow_sha256` in the user config. Unlisted repository binaries are never executed — not even for `--manifest` probing.
- **Code Quality**: Identifies `TODO`/`FIXME`/`XXX` comments and Markdown task headings, plus likely debug output in source files. String literals and non-source artifacts are excluded.
- **Independent Repository Linting**: Dedicated `lint` command runs `gofmt` and `go vet` across the entire repository to enforce formatting and catch subtle bugs without interfering with staged-only diff reviews.
- **Dependency & License Hygiene**: Dedicated `check-deps` command (and `audit --check-deps`) analyzes Go module dependencies (`go.mod` and `go.sum`), detects unused direct dependencies, duplicate/conflicting module versions, and enforces configurable dependency license allowlist/denylist rules and unknown-license policy.
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
  ],
  "license_policy": {
    "allow": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"],
    "deny": ["GPL-3.0", "AGPL-3.0"],
    "allow_unknown": false
  }
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
| `high-entropy-secret` | Entropy-based secret detection: high-entropy strings guarded by character sets (Hex, Base64, Base58), length gates, and secret contexts. |
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
| `request-taint` | Request-derived values (URL params, query, form, decoded bodies) tracked through assignments to filesystem, serving, or exec sinks (Go). |
| `wildcard-default-scope` | Permission/scope normalization that silently falls back to `"*"`/full access on empty or invalid input. |
| `plugin-trust` | Auto-execution of discovered plugins, CWD-relative plugin search paths, and credential env vars passed to plugin subprocesses. |
| `privileged-pkg-exec` | Package managers or privilege wrappers (sudo, dpkg, apt, systemctl) executed from HTTP handler code. |
| `process-kill-abuse` | Process termination whose target PID may be request-controlled. |
| `credential-in-query` | Credentials read from URL query parameters (leak via logs, history, referrers). |
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

**Go web framework rule packs (`--framework`)**

| Rule | Framework | Detects |
| --- | --- | --- |
| `gin-unhandled-binding` | Gin | Unhandled binding errors (`BindJSON`, `ShouldBindJSON`, etc.). |
| `gin-wildcard-cors` | Gin | CORS configuration with wildcard origins or AllowCredentials. |
| `gin-missing-recovery` | Gin | Gin engine initialized with `gin.New()` without Recovery middleware. |
| `gin-unsafe-param-reflection` | Gin | Route parameter or query reflected directly into response body. |
| `gin-debug-mode` | Gin | Debug mode enabled explicitly via `gin.SetMode(gin.DebugMode)`. |
| `echo-unhandled-binding` | Echo | Unhandled `c.Bind` error. |
| `echo-wildcard-cors` | Echo | Echo CORS configuration allowing wildcard origin with credentials. |
| `echo-missing-recovery` | Echo | Echo instance created without `middleware.Recover()`. |
| `echo-unsafe-param-reflection` | Echo | Echo route parameter reflected directly in response body. |
| `chi-unhandled-binding` | Chi | Unhandled Chi `render.Bind` or `render.Decode` error. |
| `chi-wildcard-cors` | Chi | Chi CORS middleware with wildcard AllowedOrigins and credentials. |
| `chi-missing-recovery` | Chi | Chi router created without `middleware.Recoverer`. |
| `chi-unsafe-param-reflection` | Chi | Chi `URLParam` reflected directly into response writer. |
| `fiber-unhandled-binding` | Fiber | Unhandled Fiber `c.BodyParser` or `c.QueryParser` error. |
| `fiber-wildcard-cors` | Fiber | Fiber CORS middleware with wildcard AllowOrigins and credentials. |
| `fiber-missing-recovery` | Fiber | Fiber application created without `recover.New()` middleware. |
| `fiber-unsafe-param-reflection` | Fiber | Fiber route parameter reflected directly in response body. |
| `http-unhandled-body-read` | net/http | Unhandled `json.NewDecoder(r.Body).Decode` error on request body. |
| `http-wildcard-cors` | net/http | Wildcard `Access-Control-Allow-Origin: *` combined with credentials. |
| `http-missing-timeouts` | net/http | HTTP server created without `ReadTimeout` / `ReadHeaderTimeout`. |
| `http-unsafe-param-reflection` | net/http | Request parameter reflected directly in HTTP response. |

### Custom Rule Authoring (`.m3tal-review-rules.yaml` or `--rules`)

Declare repository-specific custom rules in `.m3tal-review-rules.yaml` (or `.json`) in the repository root or via `--rules <path>`. Rules are strictly validated and execute with bounded regex length (<= 1000 chars) and per-rule execution timeout limits.

```yaml
version: "1.0"
rules:
  - id: custom-no-raw-sql
    name: "Disallow raw SQL query interpolation"
    severity: high
    category: security
    message: "SQL query built with concatenation; use parameterized queries"
    languages: ["go"]
    pattern: 'db\.Query\s*\([^)]*\+'
    remediation: "Use parameterized queries with placeholders ($1, ?)"
    file_exclude_pattern: '.*_test\.go$'
    timeout: "2s"
```

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
m3tal-review review --format json|jsonl|html|junit|codeclimate
m3tal-review review --snippets   # display contextual code snippets for findings in text output
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
m3tal-review audit --vuln-scan   # query OSV for known CVEs in go.mod/package.json/requirements.txt (network)

# Post results back to GitHub
m3tal-review review --check-run          # Check Run with annotations (needs GITHUB_TOKEN + GITHUB_REPOSITORY)
m3tal-review review --pr-comment         # comment on the current PR via the gh CLI
```

`audit` also accepts `--only`, `--skip`, `--fail-on`, `--format`, and `--snippets` like `review`. Policy files support per-path rule overrides via `"paths": {"<glob>": {"<rule>": {"enabled": false, "severity": "info"}}}`.

`--with-tools` uses any installed `gitleaks`, `gosec`, and `osv-scanner`; each unavailable scanner makes the requested scan incomplete. OSV Scanner may need network access to obtain vulnerability data.

`--vuln-scan` (audit only) parses `go.mod`, `package.json`, and `requirements.txt` at the repository root, queries the public [OSV API](https://osv.dev), and reports known vulnerabilities as `dependency-cve` findings with CVSS-derived severities. It performs a network request and is never enabled by default; results respect `--only`/`--skip`/`--baseline`.

`--pr-comment` posts a findings summary table to the pull request for the current branch using the `gh` CLI — `gh` must be installed and authenticated, and the checkout must be inside a PR. `--check-run` instead publishes a GitHub Check Run with per-line annotations; it requires `GITHUB_TOKEN`/`GH_TOKEN`, `GITHUB_REPOSITORY`, and `GITHUB_SHA` (or `--check-run-sha`).

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

### Repair

Generate and apply deterministic repair proposals for eligible findings inside an isolated sandbox, verified with `VerifyRemediation`:

```bash
m3tal-review repair [run-id]
m3tal-review repair --finding <id>
m3tal-review repair --rule <rule>
m3tal-review repair --dry-run
m3tal-review repair --yes
m3tal-review repair --history
```

### Report Validation

Validate report files or report directories against schema, required fields, finding IDs, check statuses, and path agreement without modifying files:

```bash
m3tal-review validate-report <path>
m3tal-review validate-report .m3tal-review/reports/ --format json
```

### History Pruning & Retention

Prune historical reports and history log entries deterministically and safely while preserving recovery-critical artifacts:

```bash
m3tal-review history prune --older-than 30d
m3tal-review history prune --keep 10 --dry-run
m3tal-review history prune --max-size 10MB --format json
```

### Suppression Audit History

Track and inspect suppression additions, edits, expiry, and removals with cryptographic tamper-evident audit trails:

```bash
m3tal-review suppressions audit
m3tal-review suppressions audit --verify
m3tal-review suppressions audit --actor alice --rule code-slop --format json
```

### Policy Dry-Run and Config Diff

Validate proposed policies and preview effective configuration differences without executing analysis or mutating files:

```bash
m3tal-review config diff proposed-policy.json
m3tal-review policy diff proposed-policy.json
m3tal-review policy dry-run proposed-policy.json --format json
```



### Environment variables

- `M3TAL_RULE_TIMEOUT` — per-rule analysis timeout (Go duration, default `2m`)
- `M3TAL_DEBUG` — print per-rule timing and finding counts to stderr

## CI Integration

Three ways to surface findings in GitHub:

**Check Run with annotations** (built-in, needs `GITHUB_TOKEN` + `GITHUB_REPOSITORY`):

```yaml
- run: m3tal-review review --check-run --check-run-sha ${{ github.sha }}
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**PR comment** (uses the `gh` CLI, no extra token handling):

```yaml
- run: m3tal-review review --pr-comment
```

**SARIF upload to code scanning** (the code-scanning API needs a token with `security_events: write`, so upload via the official action instead):

```yaml
- run: m3tal-review review --format sarif > m3tal-review.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: m3tal-review.sarif
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The SARIF output follows schema 2.1.0 (`tool.driver` + `results` with `physicalLocation`/`ruleId`), so it is accepted by `upload-sarif` and most SARIF consumers.

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
