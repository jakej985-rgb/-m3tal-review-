# Explainability & Evidence Presentation Guide

## Overview

Findings in `m3tal-review` must be understandable, reviewable, and strictly traceable to the
underlying semantic evidence that produced them. `m3tal-review` forbids invented or ungrounded
narratives: every statement in an explanation either directly maps to a recorded evidence step
or is explicitly demarcated as an inference.

## The Finding Explanation Structure

Every finding can generate an explainability object (`FindingExplanation`) containing:

- **Rule Rationale**: Explains the security or quality property the rule enforces.
- **Evidence Summary**: High-level characterization of the trace (e.g. source-to-sink,
  state-transition, lock sequence, or pattern match).
- **Evidence Steps**: Ordered sequence of verified operations (`source`, `call`, `branch`,
  `state`, `lock`, `sink`, `note`).
- **Inferences**: Statements that represent analytical heuristics or unverified assumptions,
  explicitly flagged as `is_inference: true`.
- **Severity Factors**: Deterministic justification of the severity level and risk score.
- **Confidence Rationale**: Explanation of the confidence level (`proven`, `potential`).
- **Assumptions**: Program environment conditions assumed by the analyzer (e.g. channel
  buffers, non-aliased pointers).
- **Limitations**: Bounded conditions such as execution timeouts, budget exhaustion, or
  unmodeled language constructs.
- **Prioritization & Correlation**: Why the finding was ranked with its score and clustered
  under a root correlation group.

## Redaction & Safety Bounding

To protect sensitive credentials while presenting actionable excerpts:
1. **Redaction**: Secrets, private keys, AWS access keys, GitHub tokens, Bearer tokens,
   and credential variable assignments are automatically masked with `[REDACTED]`.
2. **Bounding**: Code snippets and excerpts are strictly capped to at most 5 lines and
   400 characters to prevent report bloat and accidental leakage.

## Markdown & JSON Integration

Explanations are serialized in JSON reports under the `explanation` key on each finding, and
can be formatted into Markdown tables for PR review comments and CI logs.
