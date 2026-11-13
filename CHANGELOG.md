# Changelog

## Unreleased

### Changed
- `request-taint` findings roll up per function: multiple sinks in one
  function produce a single finding with per-site evidence, and sinks
  reached only through intra-package call edges are capped at medium for
  filesystem targets (exec/outbound stay high). This removes inflated
  per-line duplicates on shared helpers like atomicWriteFile/runCmd.
- `unpinned-action` and `unpinned-image` now key findings by the matched
  reference, so each distinct unpinned `uses:`/`image:` produces its own
  finding instead of collapsing into one per file.
- `audit --vuln-scan` and `check-deps` now cover multi-module repositories:
  manifests (go.mod, package.json, requirements.txt) are discovered by
  walking the tree (vendor/node_modules excluded, depth-bounded) instead of
  only reading root-level files, and `check-deps` reports nested-module
  hygiene findings plus license checks across all module requirements.
- `request-taint` is now package-scoped: JSON-RPC plugin packages (stdin
  scanner + `json.Unmarshal(line/req.Params, ...)`) seed taint, and taint
  propagates through intra-package call edges to a bounded fixpoint. Sinks
  now include outbound HTTP requests; struct fields named `*Path`/`*File`/
  `*Dir`/`*Root` passed to calls taint the callee parameter. Audit mode groups
  Go files by directory so cross-file flows (main.go -> helpers) are seen.
- `insecure-tls-verification` downgrades to medium when the file implements
  compensating application-layer auth (HMAC proofs, constant-time compares,
  VerifyPeerCertificate) and stays high when credential headers are sent over
  the unverified channel; the duplicate `tls-verification` Go pattern was
  removed in favor of this context-aware rule
- `actions-script-injection` is medium for trusted contexts (dispatch inputs,
  event names, SHAs) and stays high for attacker-authored contexts (issue/PR/
  comment/review bodies, head refs)
- `hardcoded-credential`, `ssrf`, and `unbounded-read` skip test files and
  fixtures; `unbounded-read` also recognizes LimitReader/CopyN/MaxBytesReader
- `debug-leftover` no longer flags fmt.Print* in files that implement a
  stdin/stdout JSON-RPC protocol (stdout is the wire channel)
- `client-timeouts` rewritten as ClientTimeoutRule: extracts the balanced
  http.Client literal and checks for a Timeout field (handles nested
  Transport/TLS/func-literal configs and skips test files)
- `actions-script-injection` now only fires inside executable workflow
  contexts (`run:`/`script:` keys and their block-scalar bodies); event
  interpolations in structural YAML keys (`ref:`, `with:` inputs, `if:`,
  `env:`) are data, not shell, and are no longer flagged
- Test/fixture awareness extended: `isTestSourceFile` recognizes `/tests/`,
  `/test/`, `/fixtures/` path segments (Python-style `tests/data/` included)
  and is applied consistently to `SecurityRule`, `EntropyRule`, and
  `SecretRule` — API-response fixtures no longer produce credential or
  entropy findings. PEM private-key blocks still flag in test paths.
- Public Google API keys (`AIza...`) are downgraded: `secret-material` no
  longer treats them as critical and `exposed-secret` reports them at medium
  with a verify-restrictions message, since client API keys are
  public-by-design in many first-party apps
- `hardcoded-credential` no longer flags URL constants (values starting with
  `https?://`) whose names merely contain token/secret/key
- `credential-file-permissions` (new): credential-named Go file writes
  (`os.WriteFile`/`os.Create`/`os.OpenFile`) with permissive explicit modes
  or implicit umask defaults, and Python `open()`/`Path.write_*` in
  credential-named functions without an explicit `0o600`/`chmod` — test
  files excluded
- `default-http-client` (new): Go calls through `http.DefaultClient` or the
  package-level `http.Get/Post/...` helpers, which carry no timeout — test
  files excluded
- Kotlin/Android coverage: `android-manifest` rule flags risky manifest
  attributes (`allowBackup`, `usesCleartextTraffic`, `debuggable`);
  `xxe` and `unbounded-read` gained Kotlin patterns (javax.xml parser
  factories, OkHttp `body.string()`/`bytes()`, HttpURLConnection
  inputStream reads); `debug-leftover` covers `printStackTrace`,
  `System.out/err.print`, and `Log.d`/`Log.v`

### Added
- `resolved-path-write` rule: files combining symlink resolution with file
  writes (containment may not cover resolved targets)
- `rpc-stdin-scanner` rule: unbounded bufio.Scanner on os.Stdin
- `cleartext-transport` and `unauthenticated-route` rules: plain-HTTP servers
  handling credentials, and parameterized routes mounted outside the
  authenticated `/api` namespace
- Manifest-declared names (plugin.yaml/spec fields) are taint sources in
  manifest-parsing files
- `coverage.complete` flag in audit reports and `confidence` on taint/trust
  findings
- `audit --with-slop`: `code-slop` is now skipped by default in audit so
  security findings are not buried under style noise
- ~95 deterministic detector rules across injection, secrets/crypto,
  transport, supply-chain/CI, IaC, and language-specific checks
- Go AST correctness suite (unclosed resources, ignored errors, unchecked
  assertions, defer-in-loop, cyclomatic proxy, and more)
- Language-aware slop analyzers for Go, JS/TS, Python, and brace languages
- Line-level checks: suppressions, commented-out code, duplicate blocks,
  trailing whitespace, long lines, mixed indentation
- Workflow: `--only`/`--skip`/`--rule`, profiles, path filters, baselines
  (`--baseline`/`--write-baseline`), six output formats (text, SARIF,
  GitHub annotations, JSON, JUnit, CodeClimate), `--check-run`,
  `--fail-on`, `--base`, `--unstaged`, `--max-diff-size`
- Commands: `diff`, `stdin`, `watch`, `doctor`, `list-rules`, `explain`,
  `install-hook`, `completions`, `history` filters + `history show`
- Policy: `.m3tal-review-policy.json` with per-rule and per-path overrides
- Robustness: parsed-diff/source/mask/read caching, parallel rules,
  per-rule timeout + panic isolation, fuzz tests, golden fixtures,
  benchmarks
- User config: `~/.config/m3tal-review/config.json`
- `audit --vuln-scan`: opt-in OSV API lookup for known CVEs in
  go.mod/package.json/requirements.txt (`dependency-cve` findings)
- `review --pr-comment`: post findings summary to the current PR via `gh`
- External analyzer plugins: `--plugin-dir`, `plugin_dir` user config, and
  `~/.config/m3tal-review/plugins`; repository-local plugins now require the
  explicit `--allow-repo-plugins` opt-in (previously loaded automatically)
- Repository plugin executables must additionally match a SHA-256 hash in the
  `plugin_allow_sha256` user config; the hash is verified before any
  `--manifest` probe, so unlisted binaries are never executed
- Incremental audit cache (`~/.cache/m3tal-review`), `history show
  --format json`, user config defaults for `audit`
- New detection rules: `request-taint` (intra-file taint from request input
  to filesystem/serving/exec sinks), `wildcard-default-scope`,
  `plugin-trust`, `privileged-pkg-exec`, `process-kill-abuse`, and
  `credential-in-query`

### Changed
- False-positive reductions: `chi-missing-recovery` accepts custom Recoverer
  middleware and skips test files; `pipe-to-shell` ignores comments/docs;
  `secret-material` ignores CI-templated credentials; `hardcoded-credential`
  ignores member access, UI masks, and lockfiles; `high-entropy-secret`
  skips lockfiles/checksums/docs/workflows; `debug-leftover` skips tooling
  dirs; `timing-unsafe-compare` and `web-storage-secrets` demoted to
  low/medium; JSX/TSX analyzer errors report at low severity;
  `plaintext-secret-storage` widened to token/secret/password columns
- `auditCacheSchema` bumped to 2 after detector semantics changed
- Fixed audit analyzing staged (index) content instead of working-tree
  content for the new taint/trust rule types: `workingTreeRules` now enables
  `WorkingTree` on `request-taint`, `wildcard-default-scope`, `plugin-trust`,
  `privileged-pkg-exec`, `process-kill-abuse`, and `credential-in-query`
- `plugin-trust` no longer flags `"plugins"` path elements inside anchored
  `filepath.Join` calls as working-directory-relative
- `server-timeouts` recognizes `http.Server` literals that configure timeout
  fields; `websocket-origin` only fires when `CheckOrigin` unconditionally
  returns true
- `request-taint` is now function-scoped (no cross-function identifier bleed),
  recognizes sanitizer/validator guards (`filepath.Base`/`Rel`, escaping,
  `strconv` parsers, `sanitize*`/`validate*` wrappers) and downgrades guarded
  functions to medium with a "verify coverage" note and `confidence` field
- `plugin-trust` detects credential env vars appended to `cmd.Env` even
  without `os.Environ()` passthrough
- Audit reports expose `coverage.complete`; `auditCacheSchema` bumped to 9

### Notes
- Detector rules are heuristic; see `docs/threat-model.md` for scope and
  `docs/fp-tuning.md` for managing false positives.
