# Releasing m3tal-review

`m3tal-review` is a single Go binary distributed from source. There is no
binary package pipeline — users build or install it with `go install`.

## Versioning

- The reported version comes from `m3tal-review version` (build metadata /
  module version fallback).
- Releases are git tags in the `vX.Y.Z` format (first tag: `v1.0.0`).
- Bump the tag only after the changes it covers are merged.

## Pre-release checks

CI (`.github/workflows/ci.yml`) runs on every push and PR:

1. `gofmt -l .` — must report no unformatted files.
2. `go vet ./...` — must be clean.
3. `go test -v -race ./...` — full suite with the race detector.
4. Benchmark smoke (`go test -bench . -benchtime 10x`).

Run the same locally before tagging:

```bash
gofmt -l .          # expect no output
go vet ./...
go test -race ./...
go build -o m3tal-review ./cmd/m3tal-review
./m3tal-review version
```

## Tagging a release

```bash
git tag -a vX.Y.Z -m "m3tal-review vX.Y.Z"
git push origin vX.Y.Z
```

There is no automated release workflow today; if one is added it must not
upload artifacts anywhere outside this repository without an explicit
decision — the tool is intentionally local-first and uploads nothing
unless `--check-run`/`--pr-comment` are requested.

## Consumer impact

Ecosystem repos (M3tal-core, m3tal-plugins, m3tal-apt-key, M3tal-Hub,
m3tal-llm) invoke `m3tal-review` as an external binary — see
[`INTEGRATION.md`](INTEGRATION.md). Breaking CLI flag or report-schema
changes should be called out in the tag message because consumers may
pin to a version.
