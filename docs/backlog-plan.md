# m3tal-review — remaining-1000 execution plan

Phased plan for the ~800 unshipped items in `docs/improvement-1000.md`.
Ordering principle: highest detection value per unit of false-positive risk,
earliest first. Every detector phase ships with tests + README notes and a
full `gofmt`/`vet`/`build`/`test` gate before push.

Status markers: `[ ]` pending, `[~]` partial, `[x]` shipped.

---

## Phase A — Detector long-tail, wave 11 (items ~A1–A50 remainder, B, C, D gaps)

Goal: finish the clearly-feasible pattern backlog before FP costs dominate.
Each wave = one commit, ~15–25 patterns, focused tests.

- [x] A11: CSV/formula injection (`=`,`+`,`-`,`@` cell prefixes on export),
      CRLF stripping gaps in mail/header builders, `html/template` dynamic
      template names, GraphQL persisted-query bypasses, additional SSTI sinks
      (Twig `display`, Blade `{!! !!}`, Jinja `|safe` variants — partially done)
- [x] A12: Secret formats round 2 — age/PGP done; add: Azure connection strings,
      JWT-shaped literals in config, `netrc`-style `[machine] login password`,
      Kubernetes Secret `data:` blocks with high-entropy values, Terraform
      `password = "..."` literals (raw-mode, filePattern `*.tf`)
- [x] A13: Transport/TLS round 2 — `wss://` downgrade checks, `ftp://`/`telnet://`
      URLs in code, `ssl.wrap_socket` legacy, `requests` `cert=` REJECT paths,
      Go `tls.Config{MinVersion: ssl30}`/SSLv3, `--proto ="-all,+SSLv3"` curl flags
- [x] A14: Auth/session round 2 — JWT `exp`/`nbf` not validated, session fixation
      (session ID not rotated on login), `remember_me` tokens without expiry,
      OAuth `state` missing on callback, password reset tokens logged/emailed raw
- [x] A15: Injection round 2 — LDAP filter `(|(...))` escapes, XPath `//user[name()='` + concat,
      SMTP command injection (`\r\n` in `RCPT TO`), IMAP command injection,
      CRLF in `Location:`/`Refresh:` headers (Go `Header().Set` raw values),
      open redirect via `//evil.com` protocol-relative URLs

**Exit criteria:** each item either ships as a pattern with a positive+negative
test, or is explicitly deferred with a one-line reason in this file.

## Phase B — Detector long-tail, wave 12 (last planned wave; items E–J remainder)

- [x] B1: Go — `//go:build` constraint surprises (`// +build` ignore),
      `reflect.Value.Method`/`Call` on user input, `plugin.Open` (done),
      `syscall.Exec`/`RawSyscall`, `ioutil.` deprecations (slop-level),
      `time.After` in loops (timer leak), `context.Background()` in request handlers
- [x] B2: Python — `__import__`/`importlib` dynamic (done partially),
      `getattr(obj, user_input)` chains, `subprocess` `shell=True` variants,
      `os.chmod`/`os.chown` on user paths, `tempfile.mktemp` (insecure),
      `assert` in security paths (done), `pickle` protocol 0, `marshal` (done)
- [x] B3: JS/TS — `import()`/`require()` dynamic (done), `ServiceWorker` scope
      abuse, `WebSocket` auth gaps, `postMessage` structured-clone gadgets,
      `Array.prototype.sort` comparator injection, `RegExp` catastrophic
      backtracking literals (ReDoS heuristics), `JSON.parse` reviver abuse
- [x] B4: JVM/.NET/Ruby-ish — `Runtime.exec` variants done; add `ProcessImpl`,
      `ScriptEngineManager`, `PowerShell` invocation, `WScript.Shell`,
      `.vbs`/`.bat` in repo flagged by filenameRule
- [x] B5: IaC round 2 — K8s `hostPath` volumes, `privileged` done, add
      `serviceAccountName: default` + automount, `readOnlyRootFilesystem` done,
      Terraform `aws_iam_policy` wildcard actions, `0.0.0.0/0` done,
      unencrypted `aws_ebs_volume`/`aws_s3_bucket` `server_side_encryption`,
      `.github/workflows` `secrets: inherit` reusable-workflow passthrough

**Exit criteria:** after this wave, detector additions pause unless a specific
item demonstrates clear FP-safety. Remaining E–J items are marked deferred.

## Phase C — Engineering leftovers (feasible, non-detector)

- [x] C1: `history --format json` done; add `history show --format json`
- [x] C2: `explain <rule>` enrichment — pull live example from a fixture map
- [x] C3: Audit cache v1 — per-file findings cache in user cache dir,
      keyed by fileDiff+rule-set+schema hash; timeout findings never cached;
      M3TAL_NO_AUDIT_CACHE=1 disables
- [x] C4: Golden-test expansion — one fixture per rule family (slop, secrets,
      injection) instead of single mega-fixture
- [x] C5: Benchmark CI guard — `go test -bench` smoke in a `make bench` target,
      optional `-benchtime` flag documented in README
- [x] C6: `--staged-only` path subset flag (include/exclude already exist —
      verify overlap, add only if missing UX)

## Phase D — Explicitly deferred (do NOT implement without new requirements)

- [ ] D1: CVE/vuln-DB lookups — needs network + data source + freshness policy
- [ ] D2: GitHub PR review-comment posting — needs API-token + repo-permission design
- [ ] D3: SARIF upload to code-scanning — same auth surface as D2
- [ ] D4: Real JS/TS parsing (tree-sitter dep) — architectural change; revisit
      only if pattern FPs become untenable
- [ ] D5: Semantic/cross-file analysis, ML detection — out of scope for a
      deterministic heuristic tool
- [ ] D6: WASM/custom rule sandbox — large project, unclear demand
- [ ] D7: LSP mode — large project, unclear demand

## Phase E — Documentation sweep (after A–C land)

- [x] E1: README detector table regenerated from `list-rules` output
- [x] E2: `docs/threat-model.md` — what the tool does/doesn't catch
- [x] E3: FP-tuning guide — how to use suppressions/policy/baseline effectively
- [x] E4: `CHANGELOG.md` or release-notes section summarizing the detector waves

---

## Execution order

A11 → A12 → A13 → A14 → A15 → B1 → B2 → B3 → B4 → B5 → C1–C6 → E1–E4.
Each lettered item = one commit minimum; waves may split further if a single
commit exceeds ~400 lines of detector code.

Stop condition: when Phase B exits, remaining work is D (deferred) + docs.
