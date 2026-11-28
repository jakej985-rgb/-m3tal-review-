# m3tal-review Master Plan

## Vision & Core Invariants

**m3tal-review** is a two-tier, multi-language code review system built around a **process invocation contract**:

1. **Orchestrator (`m3tal-review` / `review`)**
   - Owns: app discovery, file/diff scoping, parallel scheduling, result normalization & deduplication, policy gates (`--fail-on`), and reporting (`text | json | sarif`).
   - Knows **zero** language-specific rules, ASTs, or rule IDs.
   - Routes files solely by extension and `file_patterns` claims announced by each language app.
   - Never grows per-language CLI flags; per-app options pass through opaquely via app config blocks.

2. **Language Apps (`review-go`, `review-ts`, `review-python`, `review-shell`, `review-repo`, `review-rust`, `review-cpp`, `review-jvm`)**
   - Standalone executables, each runnable on its own (`review-go ./...`) and via the orchestrator.
   - Own parsing, type information, and all three detector families:
     - **Bug**: adapter over native ecosystem tooling (`go vet`, `tsc`, `ruff`/`pyright`, `shellcheck`, `cargo clippy`, `clang-tidy`) + AST correctness rules.
     - **Security**: per-language sink tables + intra-file source→sink taint.
     - **Slop**: language-specific AST signals carrying `evidence` + `confidence`, advisory by default.
   - Uniform rule-ID grammar: `<lang>/<category>/<slug>` (`bug | security | slop`).

---

## Completed Foundation
- **Phase 0 (Process Contract & Orchestrator)**: `protocol/` (`review-app/1`, exit codes `0–4`, strict validation), `internal/apps/` (discovery, repo-local refusal, `describe` handshake, `FilePatterns` routing, process-group timeout, partial-result preservation, architecture guards), `--apps`/`--no-apps` wiring in `review` and `audit`, diff stripping to prevent double reporting, and `auditCache` app-salt keying.
- **Phase 1 (Spec & Conformance)**: `spec/README.md` + `TestLanguageAppsConformance` passing against **5** apps (`review-go`, `review-ts`, `review-python`, `review-shell`, `review-repo`).
- **Phase 2 (Partial) & Phase 4**: `m3tal-review-go` standalone + 11 AST `bug`/`security`/`slop` rules; `apps/review-repo` + `audit --apps`.

---

## Remaining Multi-Stage Plan

### Stage A: Orchestrator Diagnostics (`apps list` & `apps doctor`)
**Goal:** Make app discovery, capabilities, and protocol health inspectable from the CLI.
- **A.1 `m3tal-review apps list`**
  - Discover all apps via standard precedence (`--app-path` → config → `REVIEW_APPS_PATH` → `PATH` → `<exeDir>`).
  - Print table/JSON of app name, version, path, claimed extensions/`file_patterns`, input modes, and rule counts.
- **A.2 `m3tal-review apps doctor`**
  - Re-run `--describe` against every discovered app and validate against `registry.json` + `protocol.ValidateDescribe`.
  - Report missing required apps, protocol mismatches, duplicate extension claims, and refused repo-local apps with actionable exit codes.
- **A.3 Tests**: Unit/CLI tests for `apps list` and `apps doctor` (`--format json|text`).

---

### Stage B: Full `review-go` Parity & Orchestrator De-coupling
**Goal:** Complete Go migration so legacy Go rules can be removed from `internal/review`.
- **B.1 `go vet` Adapter & Worktree Mode**
  - Declare `inputs: ["content", "worktree"]` in `internal/apps/golang/review-app.json`.
  - Run `go vet -json ./...` in worktree mode and normalize diagnostics into `go/bug/vet-*`.
- **B.2 Remaining Go AST Rules**
  - Port remaining `go_correctness.go` rules (`unclosed-resource`, `defer-before-err-check`, `typed-nil-error`, `subslice-retention`, `sync-pool-dirty-state`, `stateful-hasher-reuse`) and Go security/taint rules (`client-timeouts`, `cleartext-transport`, `credential-file-perm`, intra-file request taint).
  - Port remaining `go/slop/*` signals (`bool-if-return`, `else-after-return`, `unreachable-code`, `single-call-wrapper`).
- **B.3 Orchestrator Cleanup**
  - Delete migrated Go rules from `DefaultRules` / `categoryForRule` / `rules_doc.go` once parity tests pass.

---

### Stage C: Deepen `review-ts` & `review-python`
**Goal:** Upgrade both apps from initial AST/line scaffolds to compiler/linter-backed analyzers.
- **C.1 `review-ts` Compiler & Taint Upgrade**
  - Add `apps/review-ts/package.json` with `typescript` (`ts.createSourceFile` for `content`, `ts.Program` for `worktree`/`tsconfig.json`).
  - Implement TS AST `bug` (`async-foreach`, `async-use-effect`, `missing-radix`, `non-strict-equality`), intra-file taint `security` (`child_process`, `eval`/`new Function`, DOM XSS, `fs.*`, SSRF, prototype pollution), and AST `slop` (`AnyKeyword`, `deep-nesting`, `redundant-boolean`).
- **C.2 `review-python` Linter & Taint Upgrade**
  - Add `ruff check --output-format json` and `pyright --outputjson` adapters for `py/bug/*` (keeping `ast` fallback when absent).
  - Add Python `ast` import-alias resolver + intra-file taint (`sql-injection`, `command-injection`, `path-traversal`, `ssrf`, `ssti`, `xxe`).
  - Expand `py/slop/*` (`none-equality`, `type-equality`, `is-literal`, `empty-block`, `unreachable-code`, `deep-nesting`, `single-call-wrapper`).
- **C.3 Conformance Fixtures**
  - Add `bad.*` / `good.*` fixtures per rule and verify via `TestLanguageAppsConformance`.

---

### Stage D: Scaffold Remaining Language Apps (`review-rust`, `review-cpp`, `review-jvm`)
**Goal:** Achieve full polyglot app coverage across all major languages in `m3tal-review`.
- **D.1 `apps/review-rust`**
  - `cargo clippy --message-format=json` (`rust/bug/*`), `syn` AST security (`unsafe-without-safety`, `ffi-panic-unwind`, `async-lock-across-await`, `command-injection`, `sql-string-concat`, `insecure-tls`), and Rust slop (`unwrap-abuse`, `excessive-clone`, `deep-nesting`, `broad-allow-lint`).
- **D.2 `apps/review-cpp`**
  - `clang-tidy` / `clang++ -fsyntax-only` (`cpp/bug/*`), AST security (`unbounded-buffer`, `format-string`, `command-exec`, `alloc-integer-overflow`), and C/C++ slop (`using-namespace-header`, `c-style-cast`, `raw-owning-memory`, `redundant-null-before-delete`).
- **D.3 `apps/review-jvm`**
  - Java/Kotlin `bug` (`coroutine-global-scope`, `empty-catch`, `unbounded-body-read`, `blocking-in-suspend`), `security` (`insecure-deserialization`, `xxe`, `sqli`, `command-injection`, `android-signing-bypass`), and `slop` (`kotlin-nonnull-assertion`, `log-only-catch`, `debug-leftover`).
- **D.4 Conformance & Registry**
  - Register all three as optional in `internal/apps/registry.json` and add to `TestLanguageAppsConformance`.

---

### Stage E: `fix` Capability & Shared Formatters
**Goal:** Per-app automated remediation and standalone format parity.
- **E.1 `fix` Contract in `protocol/`**
  - Reserve and implement `fix` request/response types in `protocol/` so `internal/repair` fixers live with the language app that produced the finding.
- **E.2 Shared Renderers**
  - Extract SARIF / GitHub / JUnit formatters into a shared package so standalone `m3tal-review-<lang> ./...` supports all output formats.
