# Policy Engine & Quality Gates

## Overview

The `m3tal-review` policy engine provides deterministic, explainable quality gate enforcement
for local developer workflows, continuous integration (CI), and release pipelines. It maps
static findings, analyzer requirements, completeness signals, and suppressions into predictable
pass/fail outcomes.

## Core Capabilities

### 1. Quality Gate Policies & Thresholds

Policies define explicit criteria for repository health:
- **`max_severity`**: Threshold above which unsuppressed findings block gates (e.g. `high` blocks
  `high` and `critical`).
- **`min_confidence`**: Minimum confidence required for a finding to participate in quality gate
  evaluations (e.g. `medium` excludes unconfirmed heuristic warnings).
- **`max_risk_score`**: Aggregate compound risk threshold.

### 2. Required Analyzers & Completeness Defense

To prevent silent failures in CI pipelines:
- **`required_analyzers`**: Specifies mandatory analysis engines (e.g. `["flow", "concurrency"]`).
  If any required analyzer fails or is skipped, the quality gate fails immediately.
- **`fail_on_incomplete`**: When true, incomplete analysis or budget truncations immediately yield
  `GateIncomplete` (exit code 2), ensuring gates cannot be bypassed by resource starvation.

### 3. Hierarchical Rule Precedence

Policy rules are evaluated according to a strict deterministic hierarchy:
1. **Path Overrides (`path_overrides`)**: Exact file pattern matches take top precedence (e.g.,
   allowing elevated findings in `test/*` or disabling specific rules for generated code).
2. **Directory Globs**: Directory-level overrides (e.g. `legacy/*`).
3. **Repository Defaults**: Base policy values specified in root configuration.

### 4. Suppression Governance

Suppressions must satisfy audit standards:
- **`require_reason`**: Mandatory substantive justification (minimum 5 characters).
- **`require_owner`**: Explicit contact handle or team owner.
- **`require_expiry` & `max_expiry_days`**: Time-bounded suppressions prevent permanent risk debt.
  Expired suppressions are automatically rejected by the gate.

### 5. CI Exit Codes & Dry-Run Mode

Quality gate evaluations produce standardized CI exit codes:
- **`0`**: Gate passed (all criteria satisfied or only informational warnings).
- **`1`**: Gate failed (unsuppressed violations or required analyzer failure).
- **`2`**: Gate incomplete (analysis was truncated or incomplete).

In dry-run mode (`--dry-run`), evaluations are strictly non-mutating and explain the gate
decision in detail without applying side effects.
