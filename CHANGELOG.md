# Changelog

## Unreleased

### Added
- `cleartext-transport` and `unauthenticated-route` rules: plain-HTTP servers
  handling credentials, and parameterized routes mounted outside the
  authenticated `/api` namespace
- Manifest-declared names (plugin.yaml/spec fields) are taint sources in
  manifest-parsing files
- `coverage.complete` flag in audit reports and `confidence` on taint/trust
  findings
- `audit --with-slop`: `code-slop` is now skipped by default in audit so
  security findings are not buried under style noise
- ~70 deterministic detector rules across injection, secrets/crypto,
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
- Audit reports expose `coverage.complete`; `auditCacheSchema` bumped to 3

### Notes
- Detector rules are heuristic; see `docs/threat-model.md` for scope and
  `docs/fp-tuning.md` for managing false positives.
