# Attack-Path & Interprocedural Security Reasoning

## Overview

The `m3tal-review` flow analyzer provides interprocedural attack-path discovery across
functions, packages, and files. By combining summary-based fixpoint dataflow analysis with
forward breadth-first reachability (`Analyzer.Flow`), the engine identifies end-to-end paths
connecting untrusted input sources to critical security sinks.

## Core Concepts

### 1. Sources, Sinks, and Sanitizers

- **Sources**: Entrypoints where external, untrusted input enters the application. Examples
  include HTTP query parameters (`r.URL.Query().Get`), path variables (`chi.URLParam`), request
  body decoders (`json.NewDecoder(...).Decode`), and exported handler parameters.
- **Sinks**: Sensitive operations capable of causing security harm if fed attacker data:
  - Command Injection: `os/exec.Command`, `exec.CommandContext`, `plugin.Open`.
  - SQL Injection: `database/sql.(*DB).Query`, `QueryRow`, `Exec`.
  - Path Traversal: `os.Open`, `os.Create`, `os.RemoveAll`, `os.WriteFile`, `ioutil.ReadFile`.
  - SSRF: Outbound HTTP requests to user-controlled URLs (`http.Get`, `http.NewRequest`).
- **Sanitizers & Guards**: Recognized validation functions that neutralize tainted input:
  - Path containment: `filepath.Clean`, `filepath.Base`, `filepath.Rel`.
  - Encoders / Parsers: `strconv.Atoi`, `strconv.ParseInt`, `url.QueryEscape`, `html.EscapeString`.
  - Custom functions: Names matching `sanitize*`, `validate*`, `verify*`, `clean*`, `allowlist*`.

### 2. Path Classifications

Every discovered path is assigned an explicit epistemic status:

- **`confirmed`**: An uninterrupted, unsanitized path exists from source to sink with all call
  targets resolved. Produces `StatusProven` findings with high confidence.
- **`potential`**: A path connects source to sink, but crosses dynamic dispatch boundaries or
  unresolved call targets. Produces `StatusPotential` findings.
- **`blocked`**: The path passes through a recognized sanitizer or validation guard before
  reaching the sink. By default, blocked paths do not emit security findings.
- **`incomplete`**: Search terminated due to budget limits or call recursion depth thresholds.
  Marked with explicit truncation diagnostics.

## Evidence Representation

Every reported attack path produces machine-readable evidence adhering to the `TraceSourceToSink`
trace kind:
- `EvidenceSource`: Identifies where external input originates.
- `EvidenceCall` / `EvidenceBranch`: Intermediate hops across call boundaries and branch conditions.
- `EvidenceSink`: The sink invocation site where the vulnerable action executes.
