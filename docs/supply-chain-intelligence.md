# Dependency & Supply-Chain Intelligence

## Overview

The `m3tal-review` supply-chain subsystem enhances third-party dependency review with contextual,
evidence-backed risk reasoning. Rather than duplicating external vulnerability databases, it
correlates static code reachability with advisory metadata, detects manifest/lockfile drift,
flags suspicious package origins, and provides software bill-of-materials (SBOM) reconciliation.

## Core Capabilities

### 1. Lockfile & Manifest Drift

Discrepancies between declared dependencies and lockfiles introduce supply-chain attacks:
- **`missing_lockfile_entry`**: A direct dependency is declared in `go.mod` (or `package.json`)
  but has no corresponding checksum entry in `go.sum`.
- **`orphan_lockfile_entry`**: Lockfile retains unreferenced components after manifest removals.
- **`checksum_mismatch`**: Hash mismatch between local lockfiles and upstream sources.

### 2. Suspicious Identity & Origin Indicators

Heuristic detectors identify risky package configurations:
- **Typosquatting**: Flags permutations of popular dependencies (e.g. `githvb.com` or lookalike
  repository names).
- **Insecure Protocols**: Flags dependencies resolved over plaintext `http://` transport.
- **Unpinned Versions**: Flags floating dependencies specified as `latest` or `*`.

### 3. Epistemic Claim Tiers & Advisory Reachability

Vulnerability findings are categorized into explicit epistemic certainty tiers:
- **`ClaimVerifiedFact`**: Exact checksum or version verified against local artifacts.
- **`ClaimExternalAdvisory`**: Advisory claims ingested from external sources (GHSA, OSV, NVD).
- **`ClaimHeuristicReachability`**: Call-graph reachability connecting repository entrypoints to
  vulnerable packages (`ReachabilityReachable`, `ReachabilityPotentiallyReachable`, or
  `ReachabilityUnreachable`).

### 4. Software Bill of Materials (SBOM) Support

Supports industry-standard CycloneDX and SPDX JSON SBOM documents:
- **Ingestion & Validation**: Automatically recognizes and parses CycloneDX v1.5 and SPDX v2.x JSON.
- **Manifest Reconciliation**: `CompareSBOMWithGoMod` flags dependencies present in code but
  missing in the SBOM, or rogue components declared in the SBOM that do not exist in code.
- **Export**: Produces valid CycloneDX JSON from repository manifests.
