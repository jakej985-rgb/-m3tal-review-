# GEMINI.md — Project Review & Engineering Instructions

`m3tal-review` is a deterministic, AI-less polyglot code auditing, grading, and repair engine written in Go (`go 1.25`).

## Build & Verification
- Run `make check` (`gofmt -l -w .`, `go vet ./...`, static binary build, `go test -race ./...`).
- Fixture verification runs via `go test -count=1 -run 'TestFixtureSuite|FuzzFixtureRules' ./internal/review/`.
- CI tests run across `ubuntu-latest`, `macos-latest`, and `windows-latest`; keep filesystem and process
  handling Windows-safe (volume names in `filepath.Rel`, `.exe` suffix on binaries, no reliance on
  POSIX `0111` permission bits on Windows).

## Architecture Boundaries
- `cmd/m3tal-review/` and `cmd/m3tal-review-*`: thin CLI entrypoints delegating to `internal/cli/`
  and `internal/apps/`.
- `internal/cli/`: command parsing, GitHub/output formatting, and orchestrator wiring only. Do not
  place language heuristic or detection logic here.
- `internal/repository/scanner/`, `internal/detection/`, `internal/planning/`, `internal/analyzers/`:
  unified multilingual scan -> detect -> plan -> execute pipeline. Keep symlink/root containment
  checks fail-closed.
- `internal/apps/`: orchestrator (`discovery.go`, `orchestrator.go`) and `review-app/1` language
  adapters (`bug`, `security`, `slop`). Never execute repo-local binaries during auto-discovery,
  respect `AddedLines` in review mode, honor `--only`/`--skip` rule filters, and surface
  incomplete or failed runs to callers.
- `internal/review/` & `internal/review/history/`: `internal/review/history` must never import `internal/review`.
- `internal/experimental/`: quarantined work — must not be imported by production CLI or analyzer paths.

## Code Review Guidelines
- Skip formatting, indentation, or import-order comments; `gofmt -l .` is strictly enforced in CI.
- Prioritize correctness, security (path/symlink traversal, command or workflow script injection,
  fail-open guards), cross-platform behavior, and false-positive/false-negative prevention in
  AST/slop analyzers.
- Expect regression tests for bug fixes, security fixes, and new analyzer or CLI behaviors.
