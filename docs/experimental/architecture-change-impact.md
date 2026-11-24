> **Experimental status.** This feature is implemented and unit-tested but is not wired into the CLI. See `internal/experimental/README.md`.

# Repository Architecture & Change-Impact Intelligence

## Overview

The `m3tal-review` architecture subsystem provides an incremental dependency and boundary model
of the repository. It analyzes package structures, verifies architectural layer constraints,
detects circular dependencies, computes change blast radiuses, and maintains a cached graph
with correctness-first invalidation.

## Core Capabilities

### 1. Package Dependency Graph & Cycles

The engine constructs an `ArchitectureGraph` by parsing Go abstract syntax trees across all
packages in the repository.
- **Exported Symbols**: Identifies public API entrypoints and interfaces.
- **Internal Imports**: Tracks all intra-repository module dependencies.
- **Cycle Detection**: Applies Tarjan / DFS cycle detection to uncover illegal dependency loops.
- **Resource Limits**: When budget limits (`MaxNodes`, `MaxDepth`) are reached, the engine flags
  the graph as `Truncated` and emits explicit `GraphDiagnostic` limit warnings, avoiding silent
  claim reductions.

### 2. Architectural Boundaries & Layer Policies

Repository layers are enforced via versioned `ArchitecturePolicy` rules:
- **`semantic-isolation`**: Core semantic IR models (`internal/semantic*`) must not import
  higher analysis engines (`internal/analysis*`) or review pipelines.
- **`analysis-isolation`**: Static analysis packages must not import the review orchestrator or
  command entrypoints (`cmd*`).
- **`review-isolation`**: Review orchestration core must remain independent from CLI commands.

Boundary violations record precise source file spans, line numbers, and the breached policy rule.

### 3. Change-Impact Intelligence & Blast Radius

Given a set of modified files or packages, `EstimateImpact` computes the reverse dependency closure:
- **`ImpactExact` (Distance 1)**: Direct dependents importing the changed package.
- **`ImpactHeuristic` (Distance >= 2)**: Transitive cascade through the reverse dependency graph.
- **Affected Targets**: Automatically maps the blast radius to affected static analyzers and
  test targets for targeted verification.

### 4. Graph Caching & Correctness-First Invalidation

The graph cache preserves precomputed package nodes and content hashes:
- **Integrity**: Validated against package file hashes and policy configuration hashes.
- **Correctness-First**: Any modification to configuration or package files invalidates the
  cache, forcing incremental re-computation of the affected subgraph.
