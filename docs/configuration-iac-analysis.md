# Configuration, Infrastructure & Multi-Artifact Co-Review

## Overview

Modern software vulnerabilities often stem from mismatches between application code
and infrastructure configurations or misconfigurations within deployment manifests.
`m3tal-review` provides deterministic static analysis for configuration artifacts
including Dockerfiles, GitHub Actions workflows, Kubernetes manifests, and Terraform
HCL definitions, alongside cross-artifact co-review analysis.

## Analyzers

### 1. Dockerfile Security (`AnalyzeDockerfile`)
- **Root User Execution (`docker-root-user`)**: Identifies images that do not declare
  a non-root `USER` directive before execution.
- **Floating/Mutable Tags (`docker-floating-tag`)**: Identifies `FROM` instructions
  using `:latest` or omitted tags, recommending immutable sha256 digests.
- **Sudo / Privilege Escalation (`docker-sudo-usage`)**: Identifies unnecessary sudo
  package installations or invocations inside container layers.

### 2. GitHub Actions Workflows (`AnalyzeWorkflow`)
- **Script Injection (`gha-script-injection`)**: Detects untrusted user-controlled
  context expressions (e.g. `github.event.issue.title`, `github.event.comment.body`)
  inlined directly into shell `run:` steps.
- **Excessive Permissions (`gha-write-all-permissions`)**: Detects `permissions: write-all`
  or dangerous scope declarations violating the principle of least privilege.
- **Unpinned Actions (`gha-unpinned-action`)**: Recommends pinning actions to full commit
  SHAs rather than floating branch or tag names.

### 3. Kubernetes Manifests (`AnalyzeKubernetes`)
- **Privileged Containers (`k8s-privileged-container`)**: Flags `privileged: true`.
- **Root UID Execution (`k8s-run-as-root`)**: Flags `runAsNonRoot: false` or `runAsUser: 0`.
- **Host Namespace Sharing (`k8s-host-namespace`)**: Flags `hostNetwork: true`,
  `hostPID: true`, or `hostIPC: true`.
- **Missing Resource Limits (`k8s-missing-resource-limits`)**: Ensures CPU and memory
  limits are specified to prevent cluster resource starvation.

### 4. Terraform & IaC (`AnalyzeTerraform`)
- **Overly Permissive Ingress (`iac-open-ingress`)**: Identifies security group rules
  opening administrative ports (22, 3389) to universal ingress CIDRs (`0.0.0.0 / 0`).
- **Wildcard IAM Policies (`iac-wildcard-iam`)**: Flags statements granting wildcard
  actions across cloud services.
- **Unencrypted Storage (`iac-unencrypted-storage`)**: Identifies storage resources
  (such as S3 buckets) lacking server-side encryption configurations.

## Multi-Artifact Co-Review

Multi-artifact co-review correlates definitions across heterogeneous files:
- **Container Port Mismatch (`coreview-port-mismatch`)**: Correlates Dockerfile `EXPOSE`
  directives with Kubernetes `containerPort` configurations to surface unrouted services
  or deployment drift.
- **Unauthenticated Sensitive Routes (`coreview-unauthenticated-endpoint`)**: Correlates
  API routing specifications (OpenAPI / route maps) with required authentication schemes
  for administrative endpoints (`/admin`, `/internal`).
