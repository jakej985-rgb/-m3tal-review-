# Analyzer fixtures

Fixture-driven tests for M3TAL Review analyzers (rules implementing
`internal/review.Rule`). Every analyzer should have at least one **positive**
(must fire) and one **negative** (must stay silent) fixture before it is
considered complete; boundary fixtures cover nested syntax, multiple matches,
path/position advancement, permissions, quoting, and other rule-specific edge
cases.

## Layout

```
testdata/fixtures/<rule>/<case>/
    input.diff     unified diff fed to Rule.Check (required)
    expect.yaml    expected findings (required)
    golden.json    optional deterministic JSON snapshot of all findings
```

`<rule>` is the rule ID (e.g. `exposed-secret`) and must match a constructor
registered in `fixtureRules()` in `internal/review/fixture_test.go`. `<case>`
is a short kebab-case name describing the scenario.

## expect.yaml

Expected findings are asserted by **rule, file, line, severity, and an optional
message substring** — never by full-output snapshots, so tests survive
remediation/message wording changes:

```yaml
findings:
  - rule: exposed-secret        # optional; defaults to the fixture dir name
    file: config.go             # optional; empty means "any file"
    line: 3                     # optional; 0/omitted means "any line"
    severity: high              # optional
    message_contains: aws token # optional substring of the finding message
```

The entry count must equal the finding count exactly: missing findings,
unexpected extra findings, and findings at the wrong location all fail with a
minimal diff listing `expected but not found` vs `unexpected finding` lines.

Use `findings: []` for negative fixtures.

## Running

```sh
# Fast fixture suite only (also runs as part of `go test ./...`)
go test ./internal/review/ -run TestFixtureSuite -count=1

# Single rule or case substring
go test ./internal/review/ -run TestFixtureSuite -fixture exposed-secret

# Race-enabled run
go test -race ./internal/review/ -run 'TestFixtureSuite|FuzzFixtureRules' -count=1
```

## Registering a new analyzer

1. Add its constructor to `fixtureRules()` in `internal/review/fixture_test.go`.
2. Create `testdata/fixtures/<rule-id>/<case>/input.diff` + `expect.yaml`.
3. `TestFixtureSuite` picks it up automatically — no bespoke test runner.

## Golden files

`golden.json` is an optional byte-exact JSON snapshot of the sorted findings,
for the rare cases where the serialized shape itself is the contract (report
serialization, stable IDs). Prefer `expect.yaml` field assertions everywhere
else. `-fixture-update` regenerates an existing `golden.json`.

## Promoting fuzz / regression failures

Crashes, timeouts, and false positives discovered by fuzzing or production
should be retained as permanent fixtures:

1. Save the reproducer diff as `testdata/fixtures/<rule>/<case>/input.diff`.
2. Run `go test ./internal/review/ -run TestFixtureSuite -fixture-update`
   to generate `expect.yaml` from actual output.
3. Review the generated expectations — for a crash fix the fixture should
   assert the *correct* findings (or `findings: []`), not the `-error`
   sentinel; hand-edit `expect.yaml` and add `message_contains` as needed.
4. Commit the fixture; the case runs in the fast suite forever after.

`FuzzFixtureRules` in `internal/review/fuzz_test.go` seeds its corpus from
these `input.diff` files, so promoted fixtures also become fuzz seeds:

```sh
go test ./internal/review/ -run XXX -fuzz FuzzFixtureRules -fuzztime 60s
```

For mutation testing, run an external mutator (e.g. `go-mutesting`) against
`./internal/review/`; fixture cases give it fast, deterministic oracles.
