# `review-app/1` Conformance Specification

Every language app (`review-go`, `review-ts`, `review-python`, `review-shell`, …) must satisfy the `review-app/1` process invocation contract:

1. **Handshake (`--describe`)**:
   - Prints a single JSON `DescribeResult` to `stdout` and exits `0`.
   - `protocol` == `"review-app/1"`, `kind` == `"review-app"`.
   - Every rule ID matches `^[a-z0-9][a-z0-9_-]*/(bug|security|slop)/[a-z0-9][a-z0-9._-]{0,63}$`, and its `<category>` segment matches `rule.category`.
   - Manifest (`review-app.json`) matches `--describe` (`name`, `version`, `extensions`, `rules`).

2. **Analysis (`stdin` JSON → `stdout` JSON)**:
   - `stdout` is JSON only; logs/warnings go to `stderr`.
   - Exit codes: `0` clean · `1` findings over threshold · `2` app error/refused · `3` timeout · `4` protocol mismatch / invalid input.
   - Every `slop` finding must include non-empty `evidence` and `confidence` (`low | medium | high`).
   - When `added_lines` is non-empty on an input file, findings are scoped to those lines.

3. **Conformance Runner**:
   - Executed via `go test -race ./internal/apps -run TestLanguageAppsConformance`.
