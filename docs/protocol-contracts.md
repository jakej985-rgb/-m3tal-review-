# Versioned protocol contracts (`protocol/1`)

Protocol contracts describe the wire surface of an API — requests,
responses, headers, authentication, pairing, and capability
negotiation — in a small, versioned, language-neutral YAML/JSON
format. The `internal/analysis/protocol` package parses, validates,
and **compares** contracts: deployed versions are represented by
checked-in contract snapshots, and the comparator detects drift that
cannot be discovered by examining a single revision in isolation.

Contract documents are YAML (`.yaml`/`.yml`); JSON parses as a YAML
subset. The schema version is mandatory:

```yaml
schema_version: protocol/1
```

Any other value is rejected at parse time. Additive fields may be
introduced without a version bump; incompatible changes require a
new `protocol/N` schema handled by a new parser.

## Document structure

```yaml
schema_version: protocol/1
id: device-api                  # stable ID; default "protocol"
name: Device API                # optional, human-readable
version: "1.4.0"                # deployed version label (matrix bookkeeping)
description: ...

requests:                       # client -> server operations
  - name: CreateSession
    method: POST                # optional; compared when present
    path: /v1/sessions          # optional; compared when present
    fields:
      - name: device_id
        type: string            # string|integer|number|boolean|array|object|binary|null|any
        required: true
        default: null           # optional; "absent" != explicit null
        renamed_from: deviceId  # optional rename declaration (see below)

responses:                      # server -> client payloads
  - name: SessionAck
    fields:
      - name: session_id
        type: string
        required: true

headers:                        # request headers (client -> server)
  - name: X-Request-Id
    type: string
    required: false

auth:                           # optional; absent == scheme none
  scheme: bearer                 # none|bearer|basic|hmac|api-key|mtls|custom|<opaque>
  required: true                 # default true when auth is declared
  header: Authorization          # default "Authorization"

pairing:                        # optional mutual handshake exchange
  fields:
    - name: code
      type: string
      required: true

capabilities:                   # negotiable features
  - name: streaming
    type: boolean
    values: [v1, v2]             # optional allowed values
    required: false
    default: false

compat:                         # explicit compatibility declarations
  compatible_with: ["1.0.0"]    # versions this contract claims compatibility with
  breaking_changes:              # documented intentional breaks (see below)
    - element: request.CreateSession.field.ttl
      change: requiredness-changed
      direction: old-client/new-server
      reason: "ADR-14 migration window"
  assertions:                    # acknowledged semantic changes
    - element: auth.scheme
      reason: "scheme rotation covered by ADR-3"
```

### Fields

`fields` entries declare `name` (identifier: letters, digits, `_`,
not starting with a digit), `type` (default `string`), `required`
(default `false`), optional `default`, and optional `renamed_from`.
`default` distinguishes three states: absent (`<unset>`), explicit
`null`, and any scalar/collection value; defaults are compared by
value.

`renamed_from` declares that this field replaces a field of the
given name **in the older contract**. The comparator pairs the two
into a single `renamed` change instead of reporting a removal plus
an addition. `renamed_from` must differ from `name`, must not be
claimed by two fields, must not collide with a field still declared
in the same list, and must resolve to a field in the old contract —
all violations are diagnostics.

### Auth

`auth` is optional; an absent block is equivalent to `scheme: none`,
`required: false`. `required` defaults to **true** when the block is
present (an auth scheme that isn't required is almost always a
mistake). Unrecognized scheme names are accepted but produce a
warning diagnostic — the comparator still detects scheme changes;
scheme semantics are simply opaque.

### Compat declarations

`compat` carries the contract's explicit compatibility claims:

- `compatible_with` — version labels this contract claims wire
  compatibility with. It is a declaration for humans and matrix
  consumers; the comparator verifies claims structurally rather
  than trusting them.
- `breaking_changes` — documents **intentional breaking changes**.
- `assertions` — acknowledges **semantic changes** (changed
  defaults, auth-behavior changes, capability value changes) that
  cannot be proven wire-compatible or wire-incompatible from
  structure alone.

Both lists use the same `Annotation` shape:

```yaml
- element: request.CreateSession.field.ttl   # canonical element path (required)
  change: requiredness-changed               # optional change-kind filter
  direction: old-client/new-server           # optional direction filter
  reason: "..."                              # required documentation
```

An annotation suppresses **exactly** the finding for its element
path — element matching is exact, so an annotation for
`request.Foo` does not hide findings for `request.Foo.field.bar`,
and an annotation with a `change`/`direction` filter cannot suppress
a different kind or direction of change on the same element.
Annotations in **either** compared contract apply. Suppressed
changes are recorded in `Comparison.Suppressed` with the declaring
contract and reason — documentation, not silence.

## Element paths

Every change carries a canonical `element` path used by findings,
annotations, and matrix output:

| Element | Covers |
|---|---|
| `request.<name>` | request message added/removed |
| `request.<name>.method` / `.path` | method/path change |
| `request.<name>.field.<field>` | request field changes |
| `response.<name>[.field.<field>]` | response messages/fields |
| `header.<name>` | request header changes |
| `auth.scheme` / `auth.required` / `auth.header` | auth behavior |
| `pairing` / `pairing.field.<field>` | pairing exchange |
| `capability.<name>` | capability add/remove/type/values/default/required |

## Change kinds and directions

The comparator emits these change kinds: `added`, `removed`,
`renamed`, `type-changed`, `default-changed`,
`requiredness-changed`, `method-changed`, `path-changed`,
`auth-changed`, `values-changed`.

Each change is attributed to the compatibility directions it
affects:

- `old-client/new-server` — a client on the older contract talking
  to a server on the newer contract.
- `new-client/old-server` — a client on the newer contract talking
  to a server on the older contract.
- `both` — observable in (and potentially breaking) both pairings.

Direction rules follow the data flow. Request fields and headers
travel client→server; response fields travel server→client; pairing
is mutual. Examples:

- A **required request field added** breaks `old-client/new-server`
  (old clients don't send it); a **required request field removed**
  breaks `new-client/old-server` (old servers still require it).
- A **required response field removed** breaks
  `old-client/new-server`; a **required response field added**
  breaks `new-client/old-server`.
- `required` flipping optional→required breaks whichever side runs
  the older contract; required→optional breaks the opposite
  direction.
- Renames and type changes break both directions (each peer may run
  either version).

## Structural vs semantic changes

**Structural** changes (element/field removal, rename, type change,
requiredness change, method/path change, auth requiredness) are
wire-level facts reported directly, severity `medium` when breaking
and `low`/`info` when benign.

**Semantic** changes (changed defaults, auth scheme/header
behavior, capability values/requiredness/defaults) cannot be proven
wire-compatible or wire-incompatible from structure alone. They are
emitted as `StatusPotential` findings with a note that an explicit
`compat.assertions` (or `breaking_changes`) entry is required;
matching annotations suppress them. This keeps structural
incompatibilities strictly separate from semantic changes that
require explicit contract assertions.

Findings are `StatusProven` only when both contracts pass `Check`
with no error diagnostics **and** the change is structural;
otherwise they are `StatusPotential`. All findings are
`analysis.Finding` values (`RuleID: protocol-compat`, category
`drift`) with `change_kind`, `element`, `directions`,
`structural`, `old_contract`, and `new_contract` metadata.

## Compatibility matrix

`EvaluateMatrix` builds a client-version × server-version
compatibility matrix over a `SnapshotSet`:

```go
set, err := protocol.LoadSnapshotSet("testdata/protocol/snapshots")
res := protocol.EvaluateMatrix(set, []string{"1.0.0", "1.1.0", "2.0.0"})
// res.Cells[client][server] -> MatrixCell{Compatible, Breaking, Informational, Changes, Missing}
```

- Each unordered version pair is compared **once**; directional
  findings populate both `(older client, newer server)` and
  `(newer client, older server)` cells. Versions are ordered
  lexically, so deployed labels should be zero-padded or
  semver-sortable.
- A cell is `Compatible` when it has no unsuppressed finding with
  breaking severity (`medium`+); low/info findings are listed under
  `Informational`.
- `res.Findings` is the deduplicated union for report consumers.

### Missing historical snapshots

`versions` is the authoritative list of deployed versions the caller
believes exist. A version with no snapshot produces a **warning
diagnostic** (`missing protocol snapshot for deployed version ...`)
and its matrix cells are marked `Missing`/skipped — the analyzer
never pretends a single checkout contains deployed-version
knowledge. Contract validation problems and comparator diagnostics
are likewise propagated into `MatrixResult.Diagnostics`.

## Limitations

- The format describes *declared* contracts. It does not extract
  contracts from source code; producing snapshots for real services
  is a separate, future concern.
- Comparisons are pairwise and syntactic: they cannot prove two
  independently-versioned schemas are semantically interchangeable
  (that is what `assertions` are for), and they do not model
  transport-level concerns (TLS, encoding, pagination) unless
  declared as fields/capabilities.
- `compatible_with` is a claim, not evidence — the matrix always
  recomputes compatibility structurally.
- Response headers, streaming/framing details, and error payloads
  are not first-class sections in `protocol/1`; model them as
  response fields, capabilities, or a future schema revision.
- Default comparison is by YAML value equality; semantically equal
  but syntactically different defaults (e.g. `300` vs `"300"`)
  are reported as changes.

## Related

- `docs/statemachine-contracts.md` — the `statemachine/1` contract
  precedent this format mirrors (schema versioning, `Check`
  diagnostics, structural binding, honesty rules).
- `docs/typestate.md` — `typestate/1` spec precedent.
- `internal/analysis` — the shared Finding/Evidence/Diagnostic
  contract all results use.
