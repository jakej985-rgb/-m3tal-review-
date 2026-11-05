# m3tal-review improvement plan

Tracked plan for 100 improvements, organized into phases ordered by
value-to-effort. Each item lists the likely touch points. All work preserves
the existing `Rule` interface, added-line attribution, and heuristic
(disclaimer-preserving) posture.

Conventions:
- New rules follow the `internal/review/*_rule.go` pattern: `ParseDiff` →
  `readRuleSource`/`fileDiffSourceBlocks` → `maskNonCode`/`offsetInComment`
  gating → `matchTouchesAdded`, registered in `defaultRules` (cli.go) and the
  audit `WorkingTree` switch.
- New slop checks extend `internal/review/slop/` analyzers (Go AST in
  `slop_rule.go`, brace languages in `flow_slop.go`/`brace_language_slop.go`,
  Python in `python_slop.go`, line-level in `line_slop.go`).
- Every detector gets positive + negative unit tests (strings/comments must
  not produce findings) and a README coverage-table update.

## Phase 1 — Workflow loop-closers (highest daily value)

| # | Item | Touch points |
|---|------|--------------|
| 83 | Inline suppression comments `m3tal-review: ignore <rule>` (+ per-line/block scope, `#`, `<!-- -->` variants) | new `suppress_rule.go` or engine filter; `diff_source.go` helpers; cli wiring |
| 84 | `.m3tal-review-ignore` file (path+rule globs, syntax mirrors policy file) | `policy_rule.go` or new `ignore_rule.go`; README |
| 85 | `--only`/`--skip` rule-name filters | `internal/cli/cli.go` arg parsing, `defaultRules` |
| 86 | Policy-file per-rule enable/severity overrides | `policy_rule.go`, policy schema docs |
| 87 | `--fail-on <severity>` exit-code control | `internal/cli/cli.go`, exit path, docs |
| 88 | `--base <ref>` mode: findings only on lines changed vs base | `internal/git`, diff plumbing, cli |
| 89 | SARIF output (`--sarif`) | new `internal/review/sarif.go`, report writer |
| 90 | GitHub Actions annotation output mode | report writer / cli flag |
| 91 | `--list-rules` command | cli.go, rule registry metadata (add `Description()`?) |
| 92 | `--explain <rule>` with examples | cli.go + per-rule doc strings |
| 93 | Stable finding fingerprints for cross-run tracking | `finding.go`, history |
| 94 | `install-hook` pre-commit installer | cli.go, git hooks write (path-safe) |

## Phase 2 — High-confidence correctness bugs

| # | Item | Touch points |
|---|------|--------------|
| 61 | Go `http.Get`/`client.Do` without `defer resp.Body.Close()` | Go AST in slop or new `resource_rule.go` |
| 62 | Go `sql.Query*` without `defer rows.Close()` | same |
| 63 | Go `os.Open`/`os.Create` without `Close` | same (heuristic, low sev) |
| 64 | Go string `+=` concat inside loops → `strings.Builder` | Go AST slop check |
| 65 | `regexp.MustCompile` inside func/loop bodies | Go AST slop check |
| 66 | Unchecked `Close`/`Write` errors on write-path files | Go AST, narrow |
| 67 | Ignored `json.Unmarshal`/`strconv.Parse*` errors | Go AST assign-stmt check (extends #ignored-call work) |
| 68 | Integer division-then-multiplication precision (`a / b * c`) | Go AST binary-expr check, low sev |
| 72 | Unchecked type assertions `v := x.(T)` without ok-form | Go AST, low sev |

## Phase 3 — Security detection: injection & execution

| # | Item | Touch points |
|---|------|--------------|
| 1 | SSRF: `http.Get`/`NewRequest`/`fetch`/`axios` non-literal URLs | new `ssrf_rule.go` |
| 2 | Command injection: `exec.Command`, `os/exec`, `child_process`, `subprocess`, `shell=True` | new `cmdinj_rule.go`; audit overlap with `shell_rule.go` first |
| 3 | Open redirect: `redirect`/`Location` header/`window.location` from request params | new `redirect_rule.go` |
| 4 | SSTI: `render_template_string`, `Template(user)`, `|safe`/`raw` filters, `{{{ }}}` | extend `eval_rule.go` or new rule |
| 5 | Prototype pollution: `obj[key]=`, `Object.assign`/deep-merge, `__proto__` | new `proto_rule.go`, JS/TS gating |
| 6 | Zip-slip: `zipfile.extractall`, `tarfile.extract`, archive member validation | new rule, Python/Java/Go APIs |
| 7 | XXE: `DocumentBuilderFactory`, `SAXParser`, `xml.etree` unsafe configs | new `xxe_rule.go` |
| 8 | LDAP/XPath injection via string-built filters | new rule (niche, low sev) |
| 9 | HTTP header/response splitting: user input into `Header().Set`/raw writes | new rule |
| 10 | Log injection via unsanitized user input | new rule, low sev |
| 11 | Mass assignment: `Object.assign(req.body)`, decode into privileged structs, `permit!` | new rule |
| 12 | `assert()` used for input validation (Python, `-O` strips) | extend eval or new rule |
| 13 | `unsafe`/`cgo` usage flag for review | Go AST or regex, info sev |
| 14 | Goroutine leaks: `go func` w/o context/cancel (Go AST) | slop or security-adjacent |
| 15 | `pprof`/`expvar`/`/debug/` endpoints in non-test code | new rule |

## Phase 4 — Security detection: secrets, crypto, transport

| # | Item | Touch points |
|---|------|--------------|
| 16 | Committed secret files by filename (`.env`, `*.pem`, `id_rsa*`, `.npmrc`, `*.keystore`, `credentials.json`) | new `secretfile_rule.go` |
| 17 | JWT `alg:none` acceptance (no algorithm pinning) | extend `secret_rule.go`/new jwt rule |
| 18 | Hardcoded JWT/session secrets (`JWT_SECRET`, `SESSION_SECRET`, …) | extend `secret_rule.go` name groups |
| 19 | TLS verify disabled: `InsecureSkipVerify`, `VERIFY_NONE`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `curl -k` | audit `tls_rule.go` coverage, extend |
| 20 | Weak KDF params: low PBKDF2 iterations, hardcoded salt/IV | extend `crypto_rule.go` |
| 21 | ECB mode / static IV in AES/CBC usage | extend `crypto_rule.go` |
| 22 | Timing-unsafe secret comparison (`==`/`===`/`strcmp`/`bytes.Equal` on secrets) | new `timing_rule.go` |
| 23 | Broaden weak-randomness: `Math.random`/`random` for IDs, nonces, salts (not just token names) | extend `crypto_rule.go` |
| 24 | World-readable/writable perms: `chmod 777`, `os.Chmod(0777)`, `umask 0` | new rule |
| 25 | CORS `*` + credentials combo | new `cors_rule.go` |
| 26 | Cookies missing `Secure`/`HttpOnly`/`SameSite` | new rule (JS/Python/Go Set-Cookie) |
| 27 | Tokens in `localStorage`/`sessionStorage` | extend xss or new rule |
| 28 | `postMessage` handlers without `event.origin` check | JS/TS rule |
| 29 | Extra HTML sinks: `insertAdjacentHTML`, `srcdoc`, `|safe`, `{{{ }}}` | extend `xss_rule.go` |
| 30 | Django `mark_safe`/`format_html` misuse audit | extend `xss_rule.go` |

## Phase 5 — Supply chain & CI

| # | Item | Touch points |
|---|------|--------------|
| 31 | Unpinned GitHub Actions (`@main`, `@latest`, no ref) | new `actions_rule.go`, YAML-line patterns |
| 32 | `pull_request_target` + head-branch checkout | same |
| 33 | `${{ github.event.* }}` interpolated into `run:` blocks | same |
| 34 | `curl | sh` / `wget -O- | bash` pipe-to-shell | extend `shell_rule.go` or new rule |
| 35 | Unpinned images: `FROM x:latest`, `image: foo:latest` | new rule (Dockerfile/compose/k8s) |
| 36 | Secrets echoed in CI (`echo $SECRET`, `${{ secrets.* }}` printed) | actions_rule |
| 37 | Missing/over-broad `permissions:` in workflows | actions_rule |
| 38 | Docker socket/privileged/hostPID/hostNetwork/cap_add ALL | new `iac_rule.go` |
| 39 | k8s missing `readOnlyRootFilesystem`/`runAsNonRoot` (heuristic, low sev) | iac_rule |
| 40 | `ADD` remote URLs / non-reproducible Dockerfile fetches | iac_rule |
| 41 | Verify `.npmrc`/`.pypirc`/`.netrc` auth tokens caught (overlap #16) | secret_rule test |

## Phase 6 — Slop: language checks

| # | Item | Touch points |
|---|------|--------------|
| 43 | Python `type(x) == T` → `isinstance` | python_slop.go |
| 44 | Python `is`/`is not` with literals; `== None` → `is None` | python_slop.go |
| 45 | Python mutable class attributes (`x = []` in class body) | python_slop.go |
| 46 | Python `global`/`nonlocal` writes | python_slop.go |
| 47 | Python `return`/`break`/`continue` inside `finally` | python_slop.go |
| 48 | Python broad `except` with log-only body (extend pass-only) | python_slop.go |
| 49 | Python `raise e` → bare `raise` (traceback loss) | python_slop.go |
| 50 | Python `assert` for validation (dedupe with #12 — pick one home) | decide placement |
| 51 | Cross-file duplicate blocks (engine-level 4-gram pass) | slop_rule.go Analyze + line_slop.go |
| 52 | JS/Python long functions & >6 params (port Go thresholds) | javascript_slop.go, python_slop.go |
| 53 | Go cyclomatic proxy: >15 branches per function | Go AST slop |
| 54 | Go `defer` inside loops | Go AST slop |
| 55 | Go `time.Sleep` in non-test code | Go AST slop, low sev |
| 56 | Go `init()` with substantial bodies | Go AST slop |
| 57 | Go `log.Fatal`/`os.Exit`/`panic` outside `main`/`cmd` | Go AST slop |
| 58 | Go unused unexported functions (whole-file, test/build-tag aware) | Go AST slop, careful |
| 59 | Go unused params → `_` convention | Go AST slop, low sev |
| 60 | `interface{}`→`any`, `ioutil` deprecations (config-gated info) | Go AST slop |

## Phase 7 — Slop: language-agnostic line checks

| # | Item | Touch points |
|---|------|--------------|
| 73 | Trailing whitespace on added lines | line_slop.go |
| 74 | Missing final newline (diff-aware) | line_slop.go |
| 75 | Mixed tabs/spaces in added lines | line_slop.go |
| 76 | Lines >120 chars (configurable) | line_slop.go |
| 77 | Extend debug rule: `console.*`, `print`, `println`, `dbg!`, `System.out.println`, `var_dump`, `dd()`/`dump()` | debug_rule.go + per-language gating |
| 78 | `debugger;`, Python `breakpoint()`, `pdb.set_trace()` | debug_rule.go |
| 79 | Multi-file banner dedup edge cases (verify no FP) | line_slop.go tests |
| 81 | >2 consecutive blank lines in added code | line_slop.go |
| 82 | Python `elif`-chain else-after-return edge coverage | python_slop.go tests |

## Phase 8 — Performance & internals

| # | Item | Touch points |
|---|------|--------------|
| 95 | Shared staged-blob read cache across rules | `rule_source.go` + engine |
| 96 | Parallel rule/file execution (worker pool) | `engine.go` |
| 97 | Incremental audit: skip unchanged files (mtime/hash cache) | cli audit path, history |
| 98 | Report delta: new/resolved findings vs last run | history.go, report |
| 99 | Fuzz `ParseDiff` + `matchesRepoPath` | `go test -fuzz`, new fuzz tests |
| 100 | Analyzer benchmarks + CI coverage gate | `*_test.go` benchmarks, CI config |

## Explicitly deferred / likely skipped

- #42 dependabot drift, #69–71 slice/loop micro-checks, #80 TODO convention —
  low signal or high FP risk; revisit only if requested.
- #50 assert-validation: implement once, in the security rules (it is a
  correctness/security issue, not style).

## Verification per item

`gofmt`, `go vet ./...`, `go build ./...`, `go test ./...`; new detectors get
dedicated `_test.go` files with positive/negative/string-literal cases; README
coverage table updated for every new rule or slop category.
