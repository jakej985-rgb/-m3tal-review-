# Robustness, Fuzzing & Mutation Testing Campaign

## 1. Overview & Strategy

`m3tal-review` enforces security and reliability boundaries through continuous fuzzing
and mutation testing across all untrusted and external inputs:
- Unified diffs and repair proposals
- JSON analysis reports and schema envelopes
- Target file paths and symlink resolution
- Semantic analyzer contracts and test suite sensitivity

---

## 2. Fuzz Targets & Bounded Resource Limits

All fuzz targets enforce strict maximum input length bounds to prevent uncontrolled
memory allocation, algorithmic complexity attacks, or catastrophic backtracking:

| Package | Fuzz Target | Input Under Test | Size Bound |
| :--- | :--- | :--- | :--- |
| `internal/repair` | `FuzzValidatePatch` | Malformed diffs & target filenames | 256 KiB / 512 bytes |
| `internal/repair` | `FuzzValidateTargetFilePath` | Repository root & relative file paths | 512 bytes |
| `internal/repair` | `FuzzApplyProposalToContent` | File content & replacement patches | 256 KiB |
| `internal/review` | `FuzzReportValidation` | Arbitrary JSON report envelopes | 256 KiB |
| `internal/review` | `FuzzParseDiff` | Raw git diffs & patch headers | 1 MiB |
| `internal/review` | `FuzzMatchesRepoPath` | Path globs & repository paths | 512 bytes |
| `internal/review` | `FuzzFixtureRules` | Diff inputs across all rule detectors | 1 MiB |

---

## 3. Mutation Testing & Sensitivity Measurement

To verify that tests do not simply pass vacuously, mutation testing
(`internal/experimental/mutation/mutation.go`) measures the suite's sensitivity by injecting synthetic
faults into verified code:
- **Lock Removal Mutants**: Eliminating critical-section locks to ensure concurrency
  analyzers detect unprotected read-after-write.
- **Boundary Inversions**: Flipping relational operators (`<` to `>`).
- **Unprotected Shared Writes**: Omitting synchronization around mutations.

### Mutation Score Metric:
$$\text{Mutation Score} = \frac{\text{Mutants Killed}}{\text{Total Mutants Evaluated}}$$

Automated verification in `internal/experimental/mutation/mutation_test.go` achieved a **100% kill rate**
against evaluated concurrency mutants.

---

## 4. Regression Retention & CI

Any crasher, timeout, or hang discovered during fuzzing campaigns must be minimized and
promoted to permanent regression fixtures under `testdata/fixtures/` or unit tests.
Smoke fuzzing and mutation tests run automatically in CI.
