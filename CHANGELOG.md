# Changelog

## Unreleased

### Added
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
- Incremental audit cache (`~/.cache/m3tal-review`), `history show
  --format json`, user config defaults for `audit`

### Notes
- Detector rules are heuristic; see `docs/threat-model.md` for scope and
  `docs/fp-tuning.md` for managing false positives.
