# M3TAL Review — Phase 0 Architecture Audit & Inventory

Generated from the current repository (78 Go packages across `cmd/`, `internal/`, `protocol/`).

---

## 1. Current Package Map & Target Destinations

| Current Package(s) | Current Responsibility | Target Destination |
|---|---|---|
| `cmd/m3tal-review` | Main CLI entrypoint | `cmd/m3tal-review` |
| `cmd/m3tal-review-{go,ts,python,shell,repo,rust,cpp,jvm}` | Standalone `review-app/1` binaries | `internal/analyzers/languages/*` + optional standalone wrappers |
| `internal/cli` | Flag parsing, `review`/`audit`/`apps`/`pr-review` runners, output formatting, config, audit cache | `internal/cli/{commands,output,configuration,integrations}` + `internal/application/` |
| `internal/git` | Git diff, staged content, working-tree file listing, branch/SHA helpers | `internal/git` + `internal/repository/scanner` |
| `internal/review/language` | `lang_checker.go` extension-to-language mapping & overrides | `internal/detection/language/` (replace extension-only logic with multi-evidence detection) |
| `internal/review` | Legacy rule registry (`DefaultRules`), `categoryForRule`, pattern/AST/taint rules, `Report`, `Finding`, `Baseline`, `Policy` | Split: engine/findings/reports/baseline/policy → `internal/review/*`; rules → `internal/analyzers/*` |
| `internal/review/slop` | Polyglot slop heuristics (`go_correctness.go`, `python_slop.go`, `javascript_slop.go`, `brace_languages.go`) | `internal/analyzers/quality/` + `internal/analyzers/languages/*` |
| `internal/apps/*` | `review-app/1` process orchestrator + 8 language apps (`bug/`, `security/`, `slop/`) | `internal/analyzers/languages/*` & `internal/planning/` |
| `internal/semantic`, `internal/semantic/golang` | Go `go/packages` + SSA frontend | `internal/semantic/{model,frontend/go}` |
| `internal/analysis/{flow,concurrency,typestate,statemachine,protocol,authproto,pipeline}` | 6 deterministic semantic engines + pipeline | `internal/semantic/{engine,analysis}` |
| `internal/deps` | Dependency & license checking, OSV/vuln scan | `internal/analyzers/dependencies/` |
| `internal/repair` | Automated deterministic fixers | `internal/repair/` |
| `internal/prreview`, `internal/prreview/github` | GitHub PR review & check-run integration | `internal/prreview/` |
| `internal/plugin` | Legacy external plugin runner | `internal/plugins/` (or consolidate with `internal/apps`) |
| `internal/benchmark` | Precision/recall/latency benchmarks | `testdata/` & benchmark suite |

---

## 2. Language Detection & Rule Inventory

- **Current Language Detection**: Concentrated in [`internal/review/language/lang_checker.go`](file:///home/m3tal/apps/m3tal-review/internal/review/language/lang_checker.go) (extension-based + `.m3tal-review` override config) and [`internal/apps/router.go`](file:///home/m3tal/apps/m3tal-review/internal/apps/router.go) (extension + `file_patterns` claims). **Gap**: no manifest, shebang, content inspection, confidence score, or `Ambiguous`/`Unknown` classification yet.
- **Language-Specific Frontends & Rules in `internal/review/`**:
  - **Go**: `go_correctness.go` (18 AST checks), `framework_packs.go` (Gin/Echo/Chi/Fiber/net/http), `tls_rule.go`, `taint_rule.go`, `dns_ssrf_rule.go`, `client_timeout_rule.go`, `transport_rule.go`, `credential_file_perm_rule.go`, `internal/semantic/golang/`.
  - **JS/TS**: `js_taint_rule.go`, `xss_rule.go`, `eval_rule.go`, `javascript_slop.go`, `internal/apps/ts/`.
  - **Python**: `python_slop.go`, `polyglot_taint.go`, `deserialization_rule.go`, `shell_rule.go`, `sqli_rule.go`, `internal/apps/python/`.
  - **Rust**: `rust_frontend.go`, `extra_rules.go` (`rust-unsafe`), `internal/apps/rust/`.
  - **C/C++**: `cpp_frontend.go`, `extra_rules.go` (`unsafe-c-functions`), `shell_rule.go`, `internal/apps/cpp/`.
  - **Java/Kotlin**: `jvm_frontend.go`, `android_signing_rule.go`, `deserialization_rule.go`, `sqli_rule.go`, `internal/apps/jvm/`.
  - **Shell/CI**: `actions_injection_rule.go`, `gh_cli_asset_rule.go`, `ci_orphaned_tests_rule.go`, `internal/apps/shell/`.

---

## 3. Overlapping `internal/experimental/` Packages

Audit of `internal/experimental/` against core packages before any promotion:
- **`experimental/policy`** vs `internal/review` policy (`--fail-on`, `.m3tal-review-policy.json`): audit & unify before promoting.
- **`experimental/lifecycle`** vs `internal/review/history`: check for overlapping history/lifecycle tracking.
- **`experimental/ecosystem`** vs `internal/deps`: check for overlapping manifest/dependency parsing.
- **`experimental/iac`** vs `internal/apps/repo` & `internal/review/extra_rules.go`: consolidate IaC rules into `internal/analyzers/infrastructure/`.
- **`experimental/arch`**, **`experimental/differential`**, **`experimental/mutation`**, **`experimental/testintel`**, **`experimental/aiassist`**: distinct capabilities; keep isolated until Phase 3/6 planner contracts are ready.

---

## 4. Phase 0 Exit Criteria Status

- [x] Existing packages mapped (78 packages accounted for).
- [x] Language detection & rule inventory documented.
- [x] Overlapping experimental packages flagged for audit prior to promotion.
- [x] Test & build baseline green (`make check` exit `0`).
- **Next**: Phase 1 — `internal/repository/` (scanner, ignore, metadata) + `internal/detection/language/` (multi-evidence detection with confidence, evidence, ambiguity, and unknown states) + `m3tal-review detect` & `m3tal-review languages`.
