# Experimental subsystems

Packages in this directory compile cleanly and have unit tests, but no
non-test package imports them: they are not reachable from `cmd/m3tal-review`
and no CLI command uses them. They were implemented as design work and are
kept here so the package graph reflects that status.

They were previously top-level `internal/` packages, which made them look
like shipped capabilities. Moving one back into `internal/` means also wiring
it into `internal/cli` (and removing any duplication with existing behavior).

| Package | Purpose | Would attach to |
| :--- | :--- | :--- |
| `aiassist` | Bounded AI-assistance engine with an offline provider and redaction boundary | review pipeline profiles |
| `arch` | Repository architecture graph, cache, and change-impact policy | audit coverage / PR context |
| `differential` | Differential verification of findings across runs | history and baseline comparison |
| `ecosystem` | GitHub Actions annotations, SARIF, and LSP adapters | `--format github`, `lsp` |
| `iac` | Dockerfile, Kubernetes, Terraform, and workflow analysis | audit rules |
| `lifecycle` | Finding lifecycle, baseline similarity, and adjudication | `history`, `--baseline` |
| `mutation` | Mutation-style test adequacy checks | test intelligence |
| `policy` | Quality-gate policy evaluation and suppression validation | `policy` command, `PolicyRule` |
| `testintel` | Test discovery, association, coverage gaps, and suggestions | test-gap rules |

Known duplication with shipped behavior (a reason these were not wired):

- `policy` overlaps `internal/review/policy_rule.go` and `suppression_audit.go`.
- `lifecycle` overlaps the existing history/baseline code.
- `iac` overlaps `shell_rule.go` and `actions_injection_rule.go`.
- `ecosystem` overlaps `internal/cli/formats.go` and `github_pr_format.go`.
- `testintel` overlaps the test-oriented rules in `internal/review`.
- `arch` overlaps `internal/analysis/pipeline`.

Documentation for these subsystems lives in `docs/experimental/`.
