# m3tal-review

`m3tal-review` is a deterministic, AI-less code auditing and grading tool
for reviewing maintainability, code quality, and security issues.

It provides actionable findings, quality grades (0–100, A–F), review trails,
and a constrained, isolated repair workflow with durable audit logging.

## Documentation

- [`docs/README.md`](docs/README.md) — documentation index: current reference, experimental subsystems, and historical material.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — package layout, command pipeline, rule engines, and storage.
- [`docs/semantic-pipeline.md`](docs/semantic-pipeline.md) — Go semantic analysis tier: SSA frontend,
  typed callgraphs, and deterministic engines.
- [`docs/INTEGRATION.md`](docs/INTEGRATION.md) — ecosystem integration, git hooks, and CI workflows.
- [`docs/RELEASE.md`](docs/RELEASE.md) — versioning, CI gates, and release tagging.
- [`docs/threat-model.md`](docs/threat-model.md) — security guarantees and non-goals.
- [`docs/history/fp-tuning.md`](docs/history/fp-tuning.md) — false-positive tuning and policy configuration.
- [`docs/AGENTS.md`](docs/AGENTS.md) — targeted agent and sub-agent team architecture and delegation guide.

## Dual-Tier Architecture

1. **Pattern & Inventory Tier (Default)**:
   - Evaluates fast, deterministic pattern/AST heuristics, structural slop detectors,
     package-scoped taint rules (Go, intra-file JS/TS), and supply-chain policies.
   - Evaluates staged changes (`review`), working trees (`audit`), or custom patches (`diff`/`stdin`).
   - Multi-language support: Go, JS/TS, Python, Java, Kotlin, C/C++, C#, Rust, Swift, PHP.
2. **Go Semantic Analysis Tier (Opt-In via `--semantic`)**:
   - Whole-program, typed SSA program model for Go via `go/packages`.
   - Six deterministic semantic engines: `flow`, `statemachine`, `typestate`,
     `concurrency`, `authproto`, and `protocol`.
   - Parallel execution, bounded budgets, and per-analyzer timeouts (`--semantic-timeout`).

## Key Features

- **Quality Grading**: Computes a deterministic 0–100 score and A–F letter grade
  based on severity-weighted finding penalties and confidence multipliers.
- **Review Engine**: `review` inspects staged Git changes (`git show :<file>`); `audit` inspects the working tree.
- **Slop Detector**: Syntax-aware analyzers detect redundant booleans, empty blocks, deep nesting (4+),
  unreachable code, and oversized functions across Go, JS/TS, Python, Java, Kotlin, C/C++, C#, Rust, Swift, and PHP.
- **Security & Supply-Chain Checks**: ~100 deterministic rules covering injection (SQL, command, SSRF, template, XXE),
  exposed secrets/keys, crypto misuse, transport security, insecure deserialization, unpinned CI actions/images,
  and IaC exposures.
- **Confidence Profiles**: `--profile full` runs `gofmt`, `go vet`, and `go test ./...` with 5-minute timeouts.
- **Optional Local Scanners**: `--with-tools` runs installed `gitleaks`, `gosec`, and `osv-scanner` binaries.
- **Dependency & License Hygiene**: `check-deps` checks Go module dependencies, unused direct deps,
  version conflicts, and SPDX license compliance.
- **Constrained Repair**: `repair` proposes and applies deterministic fixes in an
  isolated sandbox with audit logging.
- **Durable Storage**: Atomic report and history writes using `fsync` and atomic rename.
  Non-destructive `recover-history`.

## Installation

Requires Go 1.23+.

```bash
go build -o m3tal-review ./cmd/m3tal-review
# Move to PATH (e.g. /usr/local/bin)
```

## Quick Start

```bash
m3tal-review check           # Inspect git status and staged files
m3tal-review review          # Review staged changes and compute quality grade
m3tal-review audit           # Audit entire working tree (tracked + untracked)
m3tal-review history         # View past review history and grades
m3tal-review show <run-id>   # Display details of a specific past run
```

## CLI Usage Reference

### Review & Audit Workflows

```bash
# Basic review & audit
m3tal-review review                          # Review staged changes
m3tal-review review --profile full           # Add gofmt, go vet, and go test checks
m3tal-review review --with-tools             # Include gitleaks, gosec, osv-scanner
m3tal-review audit                           # Audit working tree (security rules)
m3tal-review audit --with-slop               # Include style/slop rules in audit
m3tal-review audit --include-ignored         # Include ignored files like .env
m3tal-review audit --vuln-scan               # Query OSV API for manifest CVEs (network)

# Filtering, baselines & output formats
m3tal-review review --only code-slop,secret-file --skip debug-leftover
m3tal-review review --fail-on high           # Exit non-zero only for high/critical findings
m3tal-review review --base origin/main       # Review diff relative to a base ref
m3tal-review review --baseline baseline.json # Suppress known baseline findings
m3tal-review review --format sarif           # Formats: text, json, jsonl, sarif, github, junit, html
m3tal-review review --snippets               # Show contextual source snippets in text output

# Diffs, stdin, watch & diagnostics
m3tal-review diff change.patch               # Review an arbitrary patch file
cat patch.diff | m3tal-review stdin          # Review diff from standard input
m3tal-review watch                           # Re-review whenever staged diff changes
m3tal-review doctor                          # Check git, repo, and storage health
m3tal-review list-rules                      # List all registered detector rules
m3tal-review explain <rule>                  # Explain a rule with examples and remediation
m3tal-review install-hook [--force]          # Install pre-commit hook
m3tal-review completions bash|zsh|fish       # Generate shell completions

# Pure-Code AI-Like Review System (Devin / CodeRabbit Style)
m3tal-review pr-review                       # Generate Devin-style PR walkthrough & suggestions
m3tal-review pr-review --interactive         # Triage and apply inline suggestions directly
m3tal-review pr-review --base origin/main    # Review PR diff relative to base branch
m3tal-review pr-review --post-gh             # Submit review & inline comments to GitHub PR
m3tal-review install-github-workflow         # Install turnkey GitHub Actions PR review workflow

# Opt-in Go semantic analysis
m3tal-review review --semantic
m3tal-review audit --semantic --semantic-analyzers flow,concurrency,typestate
```

### Dependency, Policy & Repair

```bash
# Dependency hygiene & licensing
m3tal-review check-deps [--strict] [--allow-licenses MIT,Apache-2.0]

# Isolated repair workflow
m3tal-review repair [run-id]                 # Interactive repair of fixable findings
m3tal-review repair --dry-run                # Verify repair in sandbox without applying
m3tal-review repair --yes                    # Apply verified repairs without prompt
m3tal-review repair --history                # Display repair audit trail

# Policy & suppression management
m3tal-review policy diff proposed.json       # Preview effective policy changes
m3tal-review policy dry-run proposed.json    # Test policy without mutating files
m3tal-review suppressions audit [--verify]   # Audit suppression log integrity
m3tal-review validate-report <path>          # Validate report against schema
m3tal-review history prune --older-than 30d  # Prune historical reports safely
```

## Deterministic Review Categories & Policy

Findings are categorized as `security`, `review`, `confidence`, `risk`, or `drift`.
Projects can configure risk and drift rules via `.m3tal-review-policy.json` in the repo root:

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

## Detector Rules Catalog

All findings come from deterministic heuristics; run `m3tal-review list-rules`
for the complete catalog and `m3tal-review explain <rule>` for remediation details.

### Core Review & Policy
| Rule | Detects |
| --- | --- |
| `todo-marker` | TODO/FIXME/XXX markers in comments and Markdown headings. |
| `debug-leftover` | Stray debug output: fmt.Print*, console.log, debugger, etc. |
| `missing-error-wrap` | `fmt.Errorf` with `%s`/`%v` instead of `%w`, losing error chain causality. |
| `review-risk` | Changed paths matching configured risk globs in policy. |
| `review-policy` | Policy violations: forbidden paths and missing coupled changes. |
| `code-slop` | Code-quality heuristics: boolean comparisons, empty blocks, deep nesting, etc. |

### Secrets, Credentials & Cryptography
| Rule | Detects |
| --- | --- |
| `hardcoded-credential` | Credential-looking variable and parameter assignments in source. |
| `exposed-secret` | High-confidence secret formats: PEM keys and tokens (AWS, GitHub, Slack, etc.). |
| `high-entropy-secret` | Entropy-based secret detection across Hex, Base64, and Base58. |
| `hardcoded-ip-address` | Hardcoded literal IP addresses in endpoints, ignoring localhost/0.0.0.0. |
| `secret-file` | Committed secret files (.env, keys, credentials). |
| `secret-material` | Credentials in source: URLs with passwords, cloud keys, auth tokens. |
| `hardcoded-session-secret` | Session/JWT secrets hardcoded in source. |
| `jwt-misuse` | JWT `none` algorithm or disabled signature verification. |
| `weak-cryptography` | MD5/SHA-1/DES/RC4 for security; math/rand for token-like values. |
| `weak-crypto-params` | ECB mode, static IVs, weak hashes, deprecated ciphers. |
| `timing-unsafe-compare` | Secret comparisons using `==`/`===` instead of constant-time comparisons. |
| `insecure-randomness` | Non-CSPRNG randomness for security-sensitive values. |
| `insecure-permissions` | Permissive permissions on sensitive files (0777/0666). |
| `terraform-secret` | Literal credentials in `.tf` files. |
| `k8s-committed-secret` | Kubernetes Secret manifests committed to the repository. |

### Injection, Concurrency & Execution
| Rule | Detects |
| --- | --- |
| `path-traversal` | File APIs fed by request input or os.Args without sanitization. |
| `request-taint` | Request/RPC values tracked to filesystem, exec, or outbound sinks. |
| `sql-injection` | String-built SQL queries via formatting/concatenation. |
| `ssrf` | Server-side request forgery: HTTP clients fetching user-controlled URLs. |
| `command-injection` | Shell/process execution built from request or interpolated data. |
| `open-redirect` | Redirect targets derived from request parameters. |
| `template-injection` | Templates rendered from user-controlled content or names. |
| `prototype-pollution` | Object merges/assignments with user-controlled keys. |
| `archive-extraction` | Archive extraction without member path validation (zip-slip). |
| `xxe` | XML parsing APIs without entity-expansion protection. |
| `goroutine-leak-candidate` | Unbounded fire-and-forget goroutines spawned without cancellation/context. |
| `dangerous-eval` | eval/exec/new Function/assert-style dynamic execution. |
| `unsafe-deserialization` | pickle/marshal/yaml.load/unserialize of untrusted data. |
| `unsafe-code` | unsafe/cgo/syscall/native-interface usage needing review. |

### Web, Client-Side & Transport
| Rule | Detects |
| --- | --- |
| `cross-site-scripting` | innerHTML/outerHTML/document.write raw HTML injection. |
| `postmessage-origin` | postMessage without origin validation or wildcard target. |
| `web-storage-secrets` | Tokens stored in localStorage/sessionStorage. |
| `cookie-flags` | Session cookies missing Secure/HttpOnly/SameSite flags. |
| `cors-misconfig` | Wildcard CORS origin combined with credentials. |
| `insecure-tls-verification` | TLS certificate verification disabled (InsecureSkipVerify). |
| `server-timeouts` | HTTP servers/clients without timeout configuration. |
| `unbounded-read` | Unbounded `io.ReadAll` on potentially large inputs. |
| `sensitive-data-logging` | Tokens, passwords, or secrets written to logs. |

### Supply Chain, CI & Infrastructure
| Rule | Detects |
| --- | --- |
| `unpinned-action` | GitHub Actions pinned to mutable branch/tag refs instead of SHAs. |
| `pull-request-target` | `pull_request_target` trigger running untrusted code with write access. |
| `actions-script-injection` | GitHub context interpolated directly into workflow `run:` blocks. |
| `pipe-to-shell` | `curl | sh` style install scripts and insecure download pipes. |
| `unpinned-image` | Container images not pinned to immutable digest SHAs. |
| `ci-secret-exposure` | Secrets echoed or exposed in CI workflow environments. |
| `container-privilege` | Privileged container flags, host namespaces, or root user. |
| `iac-exposure` | World-open CIDRs, public ACLs, wildcard IAM, unencrypted storage. |

## Slop Analyzer Language Coverage

| Language | Analysis Engine | Key Checks |
| --- | --- | --- |
| Go | Go AST (`go/parser`) | Booleans, empty blocks, nesting (4+), unreachable code, oversized functions |
| JS / TS | Structural Scanner | Booleans, non-strict equality, deep nesting, catch blocks, delimiters |
| Python | Indentation Scanner | Booleans, deep nesting, pass-only suites, mutable defaults, else after return |
| Others* | Structural Scanner | Booleans, empty blocks, deep nesting, unreachable code, boolean chains |

\* Java, Kotlin, C/C++, C#, Rust, Swift, PHP

## Custom Rule Authoring (`.m3tal-review-rules.yaml`)

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
```

## Bounded CPU Usage (`--jobs`)

By default, analysis runs across available CPU cores. `--jobs N` (or `-j N`) caps
how many analysis rules run concurrently, clamps in-process Go work via
`runtime.GOMAXPROCS`, and sets `GOMAXPROCS=N` and `GOFLAGS=-p=N` for child
processes so `go vet`, `go test`, and Go-based scanners respect the limit too.

`review`, `audit`, `watch`, `repair`, `lint`, `diff`, `stdin`, and `check-deps` all accept it:

```bash
m3tal-review audit --jobs 2
m3tal-review review --profile full --jobs 2
m3tal-review diff --jobs 2 change.patch
```

The cap reaches the Go programs those commands shell out to — `--profile full`'s
`go vet` / `go test ./...`, repair's verification `go test`, the semantic tier's
`go list`, and any Go-based `--with-tools` scanner — by setting `GOMAXPROCS` in
their environment and appending `-p=N` to `GOFLAGS`. Programs that are not
built with Go read neither setting, so `git` and non-Go scanners run uncapped;
the git calls are short-lived and dominated by the analysis they feed.

### Environment Variables

- `M3TAL_RULE_TIMEOUT` — per-rule analysis timeout (Go duration, default `2m`)
- `M3TAL_DEBUG` — print per-rule timing and finding counts to stderr

## CI Integration

### GitHub Actions Annotations
```yaml
- run: m3tal-review review --format github
```

### GitHub Check Run with Annotations
```yaml
- run: m3tal-review review --check-run --check-run-sha ${{ github.sha }}
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### SARIF Upload to GitHub Code Scanning
```yaml
- run: m3tal-review review --format sarif > m3tal-review.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: m3tal-review.sarif
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Interpreting Findings & Quality Grade

Every review run computes an executive grade:
- **Score (0–100)**: Derived by deducting weighted penalties for findings:
  - `critical`: 25 pts | `high`: 10 pts | `medium`: 4 pts | `low`: 1 pt | `info`: 0 pts
  - Confidence weighting: `high` (1.0×), `medium`/default (0.75×), `low` (0.5×)
- **Grade Scale**: A (≥90), B (≥75), C (≥60), D (≥40), F (<40)

Example terminal finding:
```
Review failed. Findings require attention.
Scope: staged
Profile: fast
Grade: B (81/100)
Run ID: 3a7f8e1c2b4d5e6a
Report: .m3tal-review/reports/3a7f8e1c2b4d5e6a.json

[high] internal/auth/token.go:42: Possible hardcoded credential assigned to password (hardcoded-credential)
  Remediation: Remove hardcoded credentials. Use environment variables or a secret management system.
```
