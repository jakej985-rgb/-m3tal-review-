# Common Semantic Model & Analyzer Contracts

## Overview

The `m3tal-review` semantic engine operates over a unified Intermediate Representation (IR)
defined in `internal/semantic/model.go`. This IR abstracts core program structures (programs,
packages, types, interfaces, functions, basic blocks, instructions, callgraphs, and memory places)
while supporting language-specific annotations through structured extension fields.

Additionally, every semantic analyzer declares a machine-readable capability specification via
`internal/analysis/capabilities.go` to provide explicit contract boundaries, epistemic guarantees,
and execution budgets.

## Semantic Model Structure

The core semantic hierarchy is structured as follows:

```
Program
  ├── Packages: []Package
  │     ├── Types: []Type
  │     ├── Functions: []Function
  │     └── LanguageExtensions: map[string]any
  ├── CallGraph: CallGraph
  ├── Contracts: []Contract
  └── LanguageExtensions: map[string]any
```

### Language Agnosticism & Extensions

Every `Program`, `Package`, and `Function` carries:
1. `Language string`: Identifies the source language (e.g., `"go"`, `"python"`, `"rust"`).
2. `LanguageExtensions map[string]any`: Stores language-specific metadata without polluting
   the common IR. Examples include language-specific concurrency runtimes, compiler flags, or
   memory model properties.

## Analyzer Capability Registry

Analyzers in `internal/analysis` publish machine-readable declarations satisfying
`AnalyzerCapability`:

### Registered Analyzers

- **`concurrency`**: Epistemic: `potential`.
  Domains: Shared state, lock inversion, race conditions. Budgets: `max-steps`, `timeout`.
- **`typestate`**: Epistemic: `proven`, `potential`.
  Domains: Resource lifecycle, leak detection. Budgets: `max-transitions`, `max-call-depth`.
- **`statemachine`**: Epistemic: `proven`, `potential`.
  Domains: Protocol state transitions, invariants. Budgets: `max-steps`, `max-instances`.
- **`flow`**: Epistemic: `proven`, `potential`.
  Domains: Taint analysis, source-to-sink reachability. Budgets: `max-origins`, `max-call-depth`.
- **`authproto`**: Epistemic: `proven`, `potential`.
  Domains: Nonce freshness, replay safety. Budgets: `timeout`.
- **`protocol`**: Epistemic: `proven`, `potential`.
  Domains: Framing, handshake sequencing. Budgets: `timeout`.

### Epistemic Guarantees

Analyzers declare their epistemic guarantees explicitly:
- **`proven`**: The property holds (or is violated) under verified mathematical or symbolic
  proof within the modeled boundaries.
- **`potential`**: A potential violation was identified via path-sensitive heuristics or
  bounded exploration, but full symbolic proof is not established.
- **Unsupported constructs**: Analyzers explicitly list constructs that fall outside their
  modeling domain (e.g., reflection, inline assembly, dynamic dispatch). When encountered,
  evaluators preserve soundness by reporting bounded or unknown statuses rather than false
  negatives.
