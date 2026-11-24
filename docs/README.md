# Documentation

Entry point for `m3tal-review` documentation. Start with
[ARCHITECTURE.md](ARCHITECTURE.md) and [threat-model.md](threat-model.md);
dated plans, audits, and release reports are under [history/](history/).

## Current reference

| Document | Contents |
| :--- | :--- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Package layout, command pipeline, rule engines, and storage. |
| [AGENTS.md](AGENTS.md) | Agent and sub-agent team architecture and delegation guide. |
| [INTEGRATION.md](INTEGRATION.md) | Git hooks, CI workflows, and editor integration. |
| [RELEASE.md](RELEASE.md) | Versioning, CI gates, and release tagging. |
| [analysis-budgets.md](analysis-budgets.md) | Analyzer budget policy and exhaustion behavior. |
| [analyzer-soundness-matrix.md](analyzer-soundness-matrix.md) | Per-analyzer soundness and known limits. |
| [attack-path-analysis.md](attack-path-analysis.md) | Attack-path reasoning across the semantic tiers. |
| [authproto-contracts.md](authproto-contracts.md) | Auth-protocol contract model and checks. |
| [concurrency.md](concurrency.md) | Concurrency model and lock/ordering checks. |
| [explainability-guide.md](explainability-guide.md) | Finding explanation and evidence fields. |
| [finding-intelligence.md](finding-intelligence.md) | Correlation, risk scoring, and prioritization. |
| [plugin-security-model.md](plugin-security-model.md) | Plugin trust and execution model. |
| [protocol-contracts.md](protocol-contracts.md) | Protocol comparator contracts and matrix. |
| [repair-security-model.md](repair-security-model.md) | Repair sandbox and approval model. |
| [report-schema-policy.md](report-schema-policy.md) | Report schema, versioning, and compatibility. |
| [robustness-fuzzing-campaign.md](robustness-fuzzing-campaign.md) | Fuzzing campaign and robustness results. |
| [semantic-model-contracts.md](semantic-model-contracts.md) | Engine-neutral semantic program model. |
| [semantic-pipeline.md](semantic-pipeline.md) | Go semantic analysis tier and deterministic engines. |
| [statemachine-contracts.md](statemachine-contracts.md) | State-machine contract language and evaluation. |
| [supply-chain-intelligence.md](supply-chain-intelligence.md) | Dependency analysis and OSV advisory integration. |
| [threat-model.md](threat-model.md) | Security guarantees and non-goals. |
| [typestate.md](typestate.md) | Typestate specifications and single-use resources. |

## Experimental

[docs/experimental/](experimental/) describes subsystems that are implemented
and tested but not wired into the CLI. Their code lives in
`internal/experimental/`; see the [package README](../internal/experimental/README.md)
for status and known duplication with shipped behavior.

## History

[docs/history/](history/) holds dated material kept for audit purposes:

- [completion-report.md](history/completion-report.md) — earlier release gate report.
- [improvement-plan.md](history/improvement-plan.md) and
  [improvement-1000.md](history/improvement-1000.md) — phased improvement backlogs.
- [backlog-plan.md](history/backlog-plan.md) — plan for the improvement backlog.
- [fp-tuning.md](history/fp-tuning.md) — earlier false-positive tuning notes.
- [audits/](history/audits/) — core, repair, semantic, and performance audits.
- [storage-split.md](history/storage-split.md) — why only history/fs ops moved out of `internal/review`.

These documents may not reflect the current codebase.
