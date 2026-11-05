# Tuning false positives

m3tal-review is heuristic; some findings will be noise. Four mechanisms, from
most local to most global:

## 1. Inline suppression (single line / file)

```go
// m3tal-review: ignore ssrf            // suppresses ssrf on this line
// m3tal-review: ignore ssrf -file      // suppresses ssrf in the whole file
```

Comment styles follow the file's language: `//`, `#`, `<!-- -->`.

## 2. `.m3tal-review-ignore` (path + rule globs)

```
# Ignore a rule in generated files
vendor/**  code-slop
*.pb.go    *
```

## 3. Policy file (per-rule and per-path)

`.m3tal-review-policy.json`:

```json
{
  "rules": {
    "code-slop": {"severity": "info"},
    "bind-all-interfaces": {"enabled": false}
  },
  "paths": {
    "*_test.go": {"code-slop": {"enabled": false}},
    "internal/tools/**": {"command-injection": {"severity": "low"}}
  }
}
```

Global `rules` apply everywhere; `paths` globs are evaluated in sorted order
and the first matching path wins for that rule.

## 4. CLI filters (per invocation)

```sh
m3tal-review review --skip code-slop,js-common-mistakes
m3tal-review review --only ssrf,command-injection,tls-verification
m3tal-review review --profile security
```

User-level defaults can live in `~/.config/m3tal-review/config.json`
(`profile`, `fail_on`, `format`, `only`, `skip`) — CLI flags always win.

## When a finding is a true positive you must keep

If the code is genuinely risky but intentional (e.g. an internal tool binding
`0.0.0.0`), suppress with a comment explaining why — future readers and
reviewers will see the justification next to the code.
