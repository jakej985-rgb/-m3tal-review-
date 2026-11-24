# Agent & Sub-Agent Team Architecture

As `m3tal-review` expands across multi-language frontends, SSA semantic analyzers, automated repair sandboxes, and GitHub pull request integrations, the project uses a specialized multi-agent architecture.

This enables developers and AI assistants to delegate specific tasks to targeted agents with scoped domain expertise and codebase boundaries.

```
                           ┌─────────────────────────┐
                           │   Main Pair Programmer  │
                           │       (Antigravity)     │
                           └────────────┬────────────┘
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
    ┌──────────────┐             ┌──────────────┐             ┌──────────────┐
    │  github_agent│             │  langmaster  │             │security_audit│
    └──────────────┘             └──────┬───────┘             └──────────────┘
                                        │
        ┌───────────────┬───────────────┼───────────────┬───────────────┐
        ▼               ▼               ▼               ▼               ▼
 ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
 │   go_lang   │ │ python_lang │ │javascript_la│ │  rust_lang  │ │dart_flutter_│
 └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
```

---

## Agent Roster

### 1. `langmaster` (Language Orchestrator)
- **Role**: Coordinates polyglot language analysis, diff taxonomy classification, and routes tasks to language specialists.
- **Key Files**:
  - `internal/review/language/` (`lang_checker.go`)
  - `internal/prreview/ast_synthesizer.go`
  - `internal/review/slop/` (`brace_language_slop.go`, `line_slop.go`)
  - `internal/review/polyglot_taint.go`
- **When to Invoke**: Multi-language diff reviews, adding new language support, calibrating global severity and grading thresholds.

---

### 2. Language-Specific Specialists (`*_lang`)

| Agent | Focus Area & Frameworks | Primary Packages | Key Test Commands |
| :--- | :--- | :--- | :--- |
| **`go_lang`** | Go AST, SSA whole-program loader, 6 semantic analyzers (`flow`, `statemachine`, `typestate`, `concurrency`, `authproto`, `protocol`), `gofmt`/`govet` | `internal/semantic/golang`, `internal/analysis/`, `internal/review/slop/go_correctness.go` | `go test ./internal/analysis/...` |
| **`python_lang`** | Python AST, indentation/nesting slop, mutable defaults, pickle/eval security, ruff/bandit | `internal/review/slop/python_slop.go`, `internal/review/deserialization_rule.go` | `go test ./internal/review/slop -run TestPython` |
| **`javascript_lang`** | JS/TS AST, intra-file taint, prototype pollution, DOM XSS, React/Vue/Node patterns | `internal/review/slop/javascript_slop.go`, `internal/review/js_taint_rule.go` | `go test ./internal/review -run TestJSTaint` |
| **`rust_lang`** | Rust AST frontend, memory safety, unsafe block tracking, `Cargo.toml` dependency hygiene | `internal/review/rust_frontend.go`, `internal/review/slop/brace_languages.go` | `go test ./internal/review -run TestRust` |
| **`jvm_lang`** | Java & Kotlin AST, Android signing/manifest, JVM deserialization (`ObjectInputStream`) | `internal/review/jvm_frontend.go`, `internal/review/android_signing_rule.go` | `go test ./internal/review -run "TestJVM\|TestAndroid"` |
| **`cpp_lang`** | C & C++ AST, memory safety, buffer boundary bounds, banned string APIs | `internal/review/cpp_frontend.go`, `internal/review/slop/brace_languages.go` | `go test ./internal/review -run TestCppFrontend` |
| **`csharp_lang`** | C# / .NET heuristics, LINQ/async anti-patterns, XML deserialization, ASP.NET | `internal/review/slop/brace_languages.go` | `go test ./internal/review/slop -run TestCSharp` |
| **`swift_lang`** | Swift AST, ARC retain cycles, iOS security models, Apple permissions | `internal/review/slop/brace_languages.go` | `go test ./internal/review/slop -run TestSwift` |
| **`dart_flutter_lang`**| Flutter UI / a11y heuristics, touch targets (48x48dp), async gaps across `BuildContext` | `internal/review/flutter_semantics_rule.go`, `internal/review/touch_target_rule.go` | `go test ./internal/review -run "TestFlutter\|TestTouch"` |
| **`php_lang`** | PHP AST heuristics, superglobal taint sinks, SQL injection, open redirects | `internal/review/slop/brace_languages.go`, `internal/review/polyglot_taint.go` | `go test ./internal/review/slop -run TestPHP` |
| **`shell_lang`** | Bash/sh scripts, pipe-to-shell, unquoted expansions, GitHub Actions injection | `internal/review/shell_rule.go`, `internal/review/actions_injection_rule.go` | `go test ./internal/review -run "TestShell\|TestActions"` |

---

### 3. Workflow & Infrastructure Specialists

| Agent | Responsibilities | Target Areas |
| :--- | :--- | :--- |
| **`github_agent`** | Pull Request lifecycle, CodeRabbit-style markdown summaries, inline suggestions, `@m3tal-review` bot commands, GitHub CLI (`gh`), CI workflows | `internal/prreview/`, `internal/prreview/github/`, `.github/workflows/` |
| **`security_audit`** | High-entropy secret scanning, credential leaks, package-scoped taint, OSV supply-chain vulnerability database queries, threat model | `internal/review/entropy_rule.go`, `internal/review/secret_rule.go`, `docs/threat-model.md` |
| **`repair_agent`** | Deterministic automated repair proposals, isolated ephemeral sandboxes, AST patch synthesis, durable repair audit logs | `internal/repair/` (`fixer.go`, `engine.go`, `sandbox.go`, `proposal.go`) |
| **`ai_review_agent`** | Ingest AI review findings, expand rules, repair PR code | `.agents/agents/ai_review_agent/` |

---

## Agent Configuration Locations

`.agents/agents/<name>/agent.md` is the single canonical, tracked location for
each agent definition. The drifted duplicate copies under the former plugin
tree were removed to keep one source of truth.

- **Workspace customizations**: `.agents/agents/<name>/agent.md` (tracked in git)
- **Global discovery**: `~/.gemini/config/agents/<name>/agent.md`

Untracked `testmaster*` definitions currently sit under `.agents/agents/` and
should be committed there or removed; they are not part of the canonical set
yet.
