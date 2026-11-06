# Integrating m3tal-review into the ecosystem

How the m3tal app repos (M3tal-core, m3tal-plugins, m3tal-apt-key,
M3tal-Hub, m3tal-llm) use this local review CLI. `m3tal-review` is the
deterministic reviewer used *across* these repositories; it is itself just a
Go binary that runs wherever `git` is available.

## Local usage

```bash
# once per machine
go build -o m3tal-review ./cmd/m3tal-review   # or install the binary on PATH

# in any ecosystem repo
cd ~/apps/M3tal-core            # or m3tal-plugins, m3tal-apt-key, M3tal-Hub, m3tal-llm
m3tal-review review             # staged changes only
m3tal-review audit              # whole working tree (slow; use periodically)
m3tal-review review --profile full   # adds gofmt/vet/go test confidence checks
```

Results land in that repo's `.m3tal-review/` directory — add it to the repo's
`.gitignore` (this repo already does). Review history (`history.jsonl`) is
per-clone local state; nothing is uploaded unless you opt into `--check-run`
or `--pr-comment`.

## Git hooks

```bash
m3tal-review install-hook          # writes .git/hooks/pre-commit running `m3tal-review review`
m3tal-review install-hook --force  # overwrite an existing hook
```

The hook resolves the real hooks dir via `git rev-parse --git-path hooks`, so
it works in worktrees and custom `GIT_DIR` layouts. It runs on staged changes
at commit time and blocks the commit (non-zero exit) when findings exceed the
`--fail-on` threshold. Ecosystem repos that prefer a shared hook can also call
`m3tal-review review` directly from their own pre-commit script.

## CI usage

See [CI.md](CI.md) for the full guide. In short, build the binary in CI and
pick one reporting channel:

```yaml
- run: go build -o m3tal-review ./cmd/m3tal-review   # or fetch a release artifact
- run: m3tal-review review --fail-on high --format sarif > m3tal-review.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: m3tal-review.sarif }
```

For PR feedback without code-scanning permissions, `--pr-comment` (needs `gh`
authenticated) or `--check-run` (needs `GITHUB_TOKEN` + `GITHUB_REPOSITORY`)
are the lighter options. `--with-tools` adds gitleaks/gosec/osv-scanner when
those binaries are installed in the runner; `audit --vuln-scan` queries the OSV
API for known CVEs in `go.mod`/`package.json`/`requirements.txt`.

## Policy per repo

Each ecosystem repo can tune behavior with a root `.m3tal-review-policy.json`
(`risk_paths`, `forbidden_paths`, `require_together`, per-rule and per-path
overrides) plus `.m3tal-review-ignore` — see [fp-tuning.md](fp-tuning.md).
The policy is read from the local working tree, so it works on staged reviews
even before the policy file itself is committed.

## M3tal-core internal review vs. m3tal-review CLI

**Important — same directory name, different things.** M3tal-core contains a
*separate, internal* review workflow (its own feature for reviewing plugin or
dashboard changes) that also writes state under a `.m3tal-review/` directory.
That workflow has its own file names, JSON schemas, and lifecycle owned by
M3tal-core code.

`m3tal-review` (this repo) is a standalone CLI with a different storage schema:

| | m3tal-review CLI | M3tal-core internal review |
| --- | --- | --- |
| Owner | this repository (`internal/review`) | M3tal-core codebase |
| History | `.m3tal-review/history.jsonl` (JSONL summaries) | M3tal-core's own format |
| Reports | `.m3tal-review/reports/<run-id>.json` (`Report` schema, see [ARCHITECTURE.md](ARCHITECTURE.md#storage-layout-m3tal-review)) | different schema |
| Trigger | CLI invocation / git hook / CI | M3tal-core internal flow |

If both run inside M3tal-core, they share only the directory *name*. They do
not read or write each other's files, and neither depends on the other. When
in doubt, check which tool produced a file: CLI reports always contain
`run_id`, `tool_version`, and a `findings` array with `rule`/`severity`
fields; `m3tal-review history` / `show <run-id>` only understand CLI reports.
