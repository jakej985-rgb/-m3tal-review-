# Report Schema & Compatibility Policy

## 1. Overview & Versioning Model

`m3tal-review` emits machine-readable analysis reports in JSON format. The canonical
schema follows Semantic Versioning (`MAJOR.MINOR.PATCH`).

The active schema version is:
```text
1.0.0
```

### Supported Version Identifiers

The report validator (`internal/review/report_validator.go`) accepts the following
identifiers for backward compatibility:
- `"1.0.0"`: Current full SemVer release.
- `"1.0"`: Minor-version alias.
- `"v1"`: Major-version prefix alias.
- `""` (empty string): Unversioned legacy reports produced by pre-v1 releases.

---

## 2. Schema Boundaries & Envelopes

A report is organized into discrete logical boundaries:

1. **Execution Metadata Envelope**:
   - `schema_version`: String indicating specification version.
   - `run_id`: 16-character lowercase hexadecimal identifier uniquely naming the run.
   - `timestamp`: UTC RFC 3339 timestamp of execution.
   - `repository`, `branch`, `commit_sha`, `base_commit_sha`, `diff_hash`: Git context.
   - `tool_version`: Version of `m3tal-review` that generated the report.
   - `passed`: Boolean verdict (`true` if no findings exceeding severity threshold).
   - `summary`: Human-readable verdict summary.

2. **Findings Tier (`findings`)**:
   - List of identified issues across pattern-matching and semantic tiers.
   - Fields: `id`, `rule`, `category`, `severity`, `file`, `line`, `message`, `commit_sha`.

3. **Check Results (`checks`)**:
   - Per-linter and per-analyzer execution statuses (`passed`, `failed`, `skipped`, `error`).

4. **Semantic Analysis Envelope (`analysis`)**:
   - `status`: `"completed"`, `"degraded"` (partial or truncated), or `"failed"`.
   - `load_error`: Frontend package loading error message if degraded or failed.
   - `program`: Summary of the analyzed typed Go AST (`packages`, `functions`, `values`).
   - `analyzers`: Per-analyzer check results.
   - `diagnostics`: Merged engine diagnostics (build errors, unsupported constructs).
   - `truncated`: Boolean indicating whether memory or time budgets halted analysis early.

5. **Coverage & Exclusions (`coverage`)**:
   - `total_files`, `first_party_files`, `vendor_files`, `unanalyzed_files`, `complete`.
   - `exclusions`: Structured list of paths excluded with categorized reasons.

6. **Attestation (`attestation`)**:
   - Integrity digest verifying report contents against execution inputs.

---

## 3. Stable Finding & Evidence Identity Rules

To ensure findings can be tracked reliably across commits, pull requests, and baselines:

1. **Line Invariance**:
   Finding IDs (`FindingID`) are computed from substantive content and deliberately exclude
   line numbers. Adding or removing lines above a finding will not change its ID.

2. **Path Normalization**:
   File paths are normalized to slash-separated relative paths without redundant `./` or
   `../` segments (e.g. `internal\\auth\\login.go` -> `internal/auth/login.go`).

3. **Substantive Signature**:
   Volatile prefixes or formatting (such as compiler line prefixes) are stripped during
   fingerprint calculation.

4. **Deterministic Sorting**:
   Reports sort findings deterministically by `(File, Line, Rule, Message)` to avoid diff
   churn across runs.

---

## 4. Integrity Checksums vs Cryptographic Signatures

`m3tal-review` distinguishes between integrity verification and cryptographic attestation:

- **Attestation Integrity Digest (`Signature` field)**:
  By default, `ComputeAttestationSignature` produces an **unkeyed, unsalted SHA-256 digest**
  over execution parameters (`version`, `repository`, `commit_sha`, `diff_hash`,
  `snapshot_hash`, `tool_version`, `timestamp`, `passed`).
  *Purpose*: Guarantees tamper-evidence against accidental modification, bit-rot, or naive
  edits.
  *Security Limitation*: It is NOT a cryptographic signature; anyone can recompute the hash.

- **Cryptographic Attestations**:
  When downstream workflows require non-repudiation or provenance guarantees (e.g. in SLSA
  or cosign pipelines), keyed HMAC or asymmetric signatures (Ed25519) should sign the
  unkeyed digest externally.

---

## 5. Migration & Compatibility Guarantees

1. **Additive Compatibility**:
   Any new field added within major version 1 MUST be optional (`omitempty` in Go struct
   tags). Consumers must ignore unknown fields when decoding.

2. **Non-Breaking Changes**:
   Removing fields, changing types, or changing field meaning requires a major version bump
   (e.g. to `2.0.0`).

3. **Golden Fixture Verification**:
   The test suite in `internal/review/schema_compat_test.go` verifies round-trip stability
   against golden fixtures stored in `testdata/report-fixtures/`.
