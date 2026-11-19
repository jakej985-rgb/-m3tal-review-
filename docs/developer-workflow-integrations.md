# Developer Workflow & Ecosystem Integrations

## Overview

`m3tal-review` integrates seamlessly into developer environments and CI/CD pipelines
via standard formats and protocols:
- **GitHub Actions**: Workflow commands, annotations, and PR check runs.
- **SARIF v2.1.0**: Standardized security reporting with codeFlow traces and remediation fixes.
- **Language Server Protocol (LSP)**: Real-time diagnostics and code actions for editors.
- **External Analyzer Normalization**: Unified ingestion with strict failure semantics.

## GitHub Actions Workflows

### 1. PR Review & Inline Annotations
To emit workflow commands that surface as line annotations in pull request diffs:
```yaml
name: Security Review
on: [pull_request]

permissions:
  contents: read
  pull-requests: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Review
        run: m3tal-review review --format github
```

### 2. SARIF Upload to GitHub Code Scanning
SARIF reports include full execution metadata, `codeFlows` (attack paths and taint steps),
and proposed fixes:
```yaml
name: Code Scanning
on:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: m3tal-review review --format sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Token Security & Scope Governance

Automated CI/CD integrations must enforce the principle of least privilege:
- **No Blanket Write Permissions**: Avoid `permissions: write-all`.
- **Secret Redaction**: GitHub PAT tokens (`ghp_`, `github_pat_`) and Bearer headers are
  automatically scrubbed from annotation logs and console outputs.
- **Audit Separation**: Integrations cannot bypass policy checks or quality gates.

## Language Server Protocol (LSP) Integration

`m3tal-review` maps semantic findings into standard LSP `Diagnostic` structures:
- **Coordinate Conversion**: 1-based internal file positions are converted to 0-based LSP ranges.
- **Severity Mapping**: Critical/High map to `Error`, Medium to `Warning`, Low to `Information`.
- **Evidence References**: Multi-step attack paths are attached as `RelatedInformation` entries.

## External Analyzer Normalization

Third-party scanners and linters are normalized into `model.Finding` records:
- **Identity Preservation**: Findings preserve original tool IDs with namespaced rules.
- **Strict Failure Semantics**: External tool failures, missing binaries, or non-zero exits
  produce explicit diagnostic errors; failures can never result in a silent pass.
