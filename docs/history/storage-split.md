# Review storage split (cleanup record)

> **Historical note.** Written during the structural cleanup; it records why
> only part of the persistence layer moved out of `internal/review`.

## What moved

The JSONL history log and the injectable filesystem primitives are now
separate packages:

- `internal/review/history` — `HistoryEntry`, `ReadHistory`,
  `AppendHistory`, retention pruning, and cross-process locking. It imports
  only the standard library plus `fsutil`/`safetext`, so it does not depend on
  `internal/review`.
- `internal/review/fsutil` — `Ops`, `Default`, `WithDefaults`, plus the
  platform-aware directory-sync and rename helpers.
- `internal/review/safetext` — terminal/log control-character escaping used by
  both packages.

`internal/review` keeps aliases and thin wrappers (`ReadHistory`,
`AppendHistory`, `PruneHistory`, `ParseRetentionDuration`,
`ParseRetentionSize`, `HistoryEntry`, `PruneOptions`/`PruneResult`) so existing
CLI call sites and package-review tests keep compiling.

## What stayed in `internal/review`

`Report`, `CheckResult`, `FindingChanges`, `AnalysisSection`, the report
writer/reader/validator, and `history_recovery.go` remain in the review
package. A clean move of the report layer is blocked by these references:

- `attestation.go`: `GenerateAttestation(*Report)`,
  `VerifyAttestation(Report)`, and `ReportAttestation` fields.
- `snippet.go`: `SnippetGenerator.AttachSnippetsToReport(*Report)` and
  `AttachSnippetsToReport(*Report, ...)`.
- `analysis_adapter.go`: `AnalysisReportFromReview(Report)`.
- `history_recovery.go`: reads `Report` files and calls `NewHistoryEntry` and
  `IsValidRunID`.
- Package-`review` tests (`storage_regression_test.go`, `platform_test.go`,
  `report_writer_test.go`, `fuzz_test.go`, `schema_compat_test.go`,
  `remediation_test.go`) call `WriteReport`/`ReadReport`/`ValidateReport`
  directly. Moving the report code to a subpackage that imports `review`
  would make those tests a `review → report → review` import cycle; moving
  the tests to `review_test` would require exporting test-only helpers and
  separate package fixtures.

Consequently the report types and validation were left in place rather than
half-migrating them. A future split should move `Report` into `review/model`
(or a new neutral package) together with `GradeResult`, `CoverageMetadata`,
and `ReportAttestation`, then update `attestation.go`, `snippet.go`,
`analysis_adapter.go`, and the storage tests in the same change.
