# authproto/1 — modeled authentication & cryptographic protocol contracts

`internal/analysis/authproto` checks *declared* authentication and
key-establishment protocol models for exploitable shapes. It is a
pragmatic modeled checker, **not a theorem prover**: it answers "given
these declarations, does the transcript admit a named attacker
capability?" and it never claims a cryptographic proof.

Contracts are YAML documents with `schema_version: authproto/1`.
JSON parses as a YAML subset. See `internal/analysis/authproto/contract.go`
for the authoritative schema.

## Attacker model

Fixed for every finding (also recorded in finding metadata):

- **Network attacker (Dolev-Yao)**: can observe, modify, drop, inject,
  and replay protocol messages; has unbounded *offline* computation
  after observing a transcript.
- The attacker **cannot** break assumed cryptographic primitives,
  cannot compromise protocol endpoints, and cannot forge proofs except
  through the weaknesses the checks look for.
- Online guessing is out of scope except where a check explicitly says
  otherwise; offline guessing exposure is the modeled concern.

## Contract format

```yaml
schema_version: authproto/1
id: my-protocol
parties: [client, server]        # optional; from/to must be members
description: ...
transcript:
  - name: challenge              # step name, unique
    from: server
    to: client
    fields:
      - name: server_nonce       # field names unique across transcript
        kind: challenge          # nonce|challenge|proof|session|key|
                                 # password|transcript-hash|signature|
                                 # metadata|other (default other)
        fresh: true              # generated fresh per run (declared)
        single_use: true         # verifier rejects reuse (declared)
        source:                  # optional function binding
          name: NewNonce
          package: example.com/x
      - name: proof
        kind: proof
        verifier:
          type: server-secret    # see verifier types below
        covers: [server_nonce]   # transcript elements the proof commits to
        derived_from: [...]      # optional KDF inputs (field names)
        kdf: hkdf-sha256         # optional; "pake" suppresses the
                                 # password-derivation finding
```

### Field properties

| Property | Meaning |
|---|---|
| `fresh` | Value generated fresh per protocol run. A *declaration*; verified against source only when `source` is bound **and** a semantic program is supplied to `Evaluate`. |
| `single_use` | The verifier rejects reuse (e.g. a used-nonce store). A *declared server-side property*, never verified. |
| `covers` | The transcript elements this field commits to. On proofs this is the transcript/session-binding claim; empty means "binds to nothing". |
| `verifier.type` | The verification construction (proof fields only). |
| `derived_from` | Field names this element's value derives from (KDF inputs). |
| `kdf` | Free-text KDF/function name; containing `pake` marks the derivation as PAKE-style. |
| `secret` | Marks low-entropy secret input (informational). |
| `source` | Structural function binding (`id`, or `name` + optional `package`/`receiver`) used by `Evaluate` to check generation claims. |

### Verifier types

| Type | Modeled meaning |
|---|---|
| `server-secret` | Proof checked against a verifier-held long-term secret (HMAC/MAC-then-compare). No offline candidate testing. |
| `public-key` | Signature/asymmetric verification. No offline candidate testing; binding still required. |
| `password` | Proof derived from a low-entropy password. **Offline candidate verification is enabled.** |
| `pake` | Password-authenticated key exchange. Offline guessing assumed prevented; PAKE soundness unverified. |
| `symmetric-key` | Pre-shared symmetric key verification. |
| `unknown` | Explicitly unmodeled → `StatusUnverified` finding. |

Any other `verifier.type` string is treated as unmodeled.

## Checks and rule IDs

| Rule | Status | Fires when |
|---|---|---|
| `authproto.offline-guessing` | potential | A proof uses `verifier.type: password`, or any field lists a `password`-kind field in `derived_from` without a `pake` KDF. |
| `authproto.replay` | potential | A proof covers no fresh value issued by the verifying party, or covers a fresh one that is not declared `single_use`. |
| `authproto.transcript-binding` | potential | A proof's `covers` omits any `nonce`/`challenge`/`session` field in the transcript. |
| `authproto.nonce-uniqueness` | potential | A `nonce`/`challenge` field is not declared `fresh`. |
| `authproto.weak-randomness` | potential | A source-bound fresh nonce/challenge reaches `math/rand` within the bounded call-graph scan (`Evaluate` only). |
| `authproto.unmodeled` | **unverified** | No proof field exists, or a proof's verifier type is missing/`unknown`/unrecognized. Never silently approved. |

### Source-derived edge (`Evaluate`)

`Analyze` is purely model-based. `Evaluate(ctx, prog, contracts, opts)`
additionally resolves each fresh nonce/challenge field's `source`
function binding against a `*semantic.Program` and scans its bounded
callee closure (default depth 3, 64 functions) for `math/rand` vs
`crypto/rand` calls:

- `math/rand` reachable → `authproto.weak-randomness` finding with the
  call-site span as evidence.
- `crypto/rand` reachable → informational diagnostic; uniqueness still
  an assumption.
- neither found → warning diagnostic; freshness remains declared-only.
- unbound/ambiguous binding → diagnostic; never guessed.

The scan is a may-analysis over call targets: it reports the worst
(randMath dominates randCrypto) and is bounded — results carry
`max-source-depth`/`max-source-functions` budgets.

## Honesty guarantees

- **No `StatusProven` findings, ever.** Model conformance and
  primitive strength cannot be proven by pattern matching.
- Model violations are `StatusPotential`: the declared model may
  diverge from the implementation.
- Unmodeled constructions are `StatusUnverified` findings, not silence.
- Every finding carries: the minimal protocol trace (one evidence step
  per transcript message up to the offending step), attacker
  capabilities (`metadata.attacker_capabilities`), required assumptions
  (`Assumptions` + `metadata.not_proven`), and a remediation hint.
- Declared-but-unverified properties (freshness without source
  binding, `single_use`, verifier strength, PAKE soundness) are
  aggregated into `Result.Assumptions` and per-finding assumptions.

## Supported patterns

Nonce-based and challenge/response transcripts, server-secret proofs
(HMAC-style), public-key signatures, password challenge/response,
PAKE declarations, symmetric-key proofs, and password-derived key
material. Anything else — custom ZK proofs, threshold schemes,
hardware-bound keys — should be declared `verifier.type: unknown` (or
omitted) and will be reported unmodeled.

## Non-goals

- No cryptographic verification (no proof that a signature verifies,
  no KDF benchmarking, no entropy measurement).
- No implementation-conformance checking beyond the narrow
  rand-source scan; binding a contract to code does not prove the code
  implements the transcript.
- No session-state exploration (that is `statemachine`'s job); the
  transcript is a single ordered exchange.
- No pipeline integration — see the roadmap issue for wiring analyzers
  into review runs.

## Fixtures

`internal/analysis/authproto/testdata/<case>/` contains self-contained
Go modules with `authproto.yaml` + `expect.yaml`, exercised by
`TestFixtureSuite` through `Evaluate` with a real `golang.Load`ed
program.
