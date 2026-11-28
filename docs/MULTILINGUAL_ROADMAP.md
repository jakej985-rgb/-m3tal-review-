# M3TAL Review — Multilingual Architecture & Refactoring Roadmap

## Core Principle

M3TAL Review is organized around one repository scanner, one detection system, one analysis planner, and a collection of specialized analyzers that all produce findings through a shared review engine:

- **Detection** determines what is in the repository.
- **Planning** determines what should run.
- **Analyzers** determine what is wrong.
- **The review engine** manages findings.
- **Output systems** communicate the results.

No language analyzer should need to know how the repository was discovered.

---

## 1. Target Architecture

```text
Repository Scanner (internal/repository/)
  └─ Discovers files, directories, manifests, and repository metadata

Detection System (internal/detection/)
  └─ Languages · Frameworks · Project types · Build systems

Analysis Planner (internal/planning/)
  └─ Selects applicable analyzers based on detection, configuration, and scope

Analyzers (internal/analyzers/) & Semantic Frontends (internal/semantic/)
  ├─ Language Analyzers (Go, Python, JS/TS, Dart, Rust, Java, C/C++, …)
  ├─ Framework Analyzers (Flutter, React, Android, .NET, …)
  ├─ Cross-Language Analyzers (security, secrets, architecture)
  ├─ Infrastructure Analyzers (Docker, Kubernetes, Terraform, GitHub Actions, Shell)
  └─ Semantic Analyzers (flow, state, concurrency, protocols, typestate, authproto)

Unified Review Engine (internal/review/)
  └─ Findings · Severity · Evidence · Suppression · Baselines · Policy · Reports

Output & Integrations (internal/cli/, internal/prreview/, internal/repair/)
  └─ CLI · JSON · SARIF · GitHub PR reviews · Repair suggestions
```

---

## 2. Language Detection Subsystem (`internal/detection/language/`)

Languages are identified using multiple evidence sources (never just extensions):

| Detection Source | Example | Priority |
|---|---|---|
| Explicit configuration | User declares a language | Highest |
| Project manifests | `go.mod`, `Cargo.toml`, `pubspec.yaml` | High |
| Known filenames | `Dockerfile`, `Makefile` | High |
| File extensions | `.go`, `.py`, `.rs` | Medium |
| Shebang | `#!/usr/bin/env python3` | Medium |
| Content inspection | Syntax and recognizable patterns | Supporting |
| Directory context | Files within a known project | Supporting |

Statuses: `detected | ambiguous | unknown | excluded`. Every detection records `Confidence` and `Evidence`.

---

## 3. Language Support Tiers & Capability Levels

- **Tier 1 (Core)**: Go (`.go`), Python (`.py`), JavaScript (`.js`, `.mjs`, `.cjs`), TypeScript (`.ts`, `.mts`, `.cts`), Dart (`.dart`), Rust (`.rs`), Java (`.java`), C/C++ (`.c`, `.h`, `.cpp`, `.hpp`).
- **Tier 2**: C# (`.cs`), Kotlin (`.kt`, `.kts`), Swift (`.swift`), PHP (`.php`), Ruby (`.rb`), Shell (`.sh`, `.bash`, `.zsh`), PowerShell, SQL, Lua, R, Scala, Elixir, Haskell, Zig.
- **Tier 3**: Solidity, Julia, Perl, OCaml, Erlang, Clojure, F#, Visual Basic, Objective-C, Assembly, WAT.

Capability matrix levels (always reported honestly, never overstated):
`Detection` → `Basic analysis` → `Static analysis` → `AST analysis` → `Semantic analysis` → `Flow analysis` → `Repair`.

---

## 4. Migration Phases

- **Phase 0**: Architecture audit and inventory (`docs/ARCHITECTURE_INVENTORY.md`).
- **Phase 1**: Repository scanner (`internal/repository/`) and multi-evidence language detection (`internal/detection/language/`).
- **Phase 2**: Framework, project, and build-system detection (`internal/detection/framework/`, `project/`, `buildsystem/`).
- **Phase 3**: Analyzer registry and execution planner (`internal/planning/`).
- **Phase 4**: Package decomposition (separating review engine, CLI commands/output/config, and analyzer contracts).
- **Phase 5**: Tier 1 language expansion, capability matrices, and semantic frontends.
- **Phase 6**: Framework, infrastructure, and cross-language security expansion.
- **Phase 7**: Performance, incremental analysis, and safe caching.
- **Phase 8**: Documentation, canonical agents, CI alignment, and release readiness.
