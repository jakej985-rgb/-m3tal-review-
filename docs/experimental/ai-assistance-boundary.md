> **Experimental status.** This feature is implemented and unit-tested but is not wired into the CLI. See `internal/experimental/README.md`.

# Deterministic-Bounded AI Assistance

## Overview

`m3tal-review` provides optional AI assistance designed to enhance explainability,
developer ergonomics, and triage velocity while strictly subordinating AI models
to the deterministic analysis engine.

Deterministic analyzers, typestate verifiers, and quality gate policies hold sole
authority over finding existence, severity classification, and repository merge status.
AI assistance outputs are strictly non-binding, advisory, and heuristic.

## Authority Invariant

The core security and correctness invariants for AI assistance include:

1. **Non-Authoritative Advice**: Model responses can never directly create, suppress,
   or modify deterministic findings, policy verdicts, or quality gates.
2. **Explicit Opt-In**: AI assistance is disabled by default (`enabled: false`, `opt_in: false`).
   The review engine operates completely offline without any model dependency.
3. **Epistemic Labeling**: Every model-generated output is explicitly stamped with
   disclaimers and warnings stating that advice is heuristic and non-authoritative.
4. **Mandatory Human Consent**: Any code remediation or regression test proposal
   requires explicit human developer approval prior to being applied to disk.
5. **Context Budget Enforcement**: Context byte size, token caps, and timeout limits
   are strictly enforced to prevent denial of service or excessive resource usage.

## Threat Model & Defenses

### 1. Prompt Injection Defense
Repository contents, diffs, commit messages, and PR descriptions are treated as
untrusted external input. The assistance engine applies defensive layers:
- **Defanging**: Common prompt injection patterns (such as instructions to override
  policy or assume developer mode) are neutralized.
- **Strict Boundary Markers**: Untrusted repository snippets are isolated inside
  explicit delimiters (`<<<UNTRUSTED_REPOSITORY_CONTENT_START>>>`).

### 2. Secret Redaction & Exfiltration Prevention
Before any repository context is formatted into an assistant prompt:
- High-entropy secrets, cloud credentials (e.g. AWS access keys), JWT tokens, and
  Bearer authorization headers are scanned and replaced with redaction placeholders.
- A cryptographic redaction log tracks sanitized positions for auditability.

### 3. Protected Configuration Integrity
Remediation proposals are validated before presentation to developers:
- Proposals attempting to alter repository configuration, `.git/`, or policy files
  (such as `.m3tal-review/policy.yaml`) are rejected.
- Proposals targeting files outside the finding's reported location are blocked.

## Providers & Offline Fallback

The assistant defines an abstract `Provider` interface declaring:
- `Name() string`: Returns the provider identifier.
- `GenerateAdvice(ctx, req) (*AssistanceResponse, error)`: Evaluates advice requests under budget.

When no remote provider is configured or network connectivity is absent, the
`OfflineProvider` generates deterministic local heuristics for explanations,
review summaries, coverage hypotheses, and triage rankings without network requests.
