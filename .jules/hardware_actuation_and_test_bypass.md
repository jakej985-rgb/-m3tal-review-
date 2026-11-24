## 2026-11-23 - Unverified Hardware Actuation and Test Assertion Bypass Rules

**Learning:** Six recurring classes of silent failure escaped AST inspections:
1. **Unverified Hardware Actuation (`unverified-hardware-actuation`):** Bridges and
transports transmitting hardware actuator commands (e.g. `PIN:13:OUTPUT`, `LED:ON`,
or emergency stop sequences) frequently assumed actuation success upon wire
transmission rather than awaiting explicit device acknowledgments (`ACK:`, `PONG:`,
`PIN13:LOW`). In safety-critical or physical microcontroller environments, an
unacknowledged transmission leaves hardware in an active/dangerous state while local
state mirrors a false safe state. Furthermore, sending actuator commands before
protocol handshake negotiation exposes unverified firmware to corrupted states.
ACK-guard scoping must verify affirmative acknowledgments (rejecting negative
checks and local telemetry state), respect switch-case labels (stopping at non-ACK
labels like `case PacketType.error:`), climb enclosing branch scopes for nested
checks (e.g. `if (mounted)` inside `if (ack.isSuccess)`), and require conjunction
(`&&`) rather than optional disjunction (`||`) for protocol verification.
2. **Early Stop Acknowledgment Overwrite:** When stop commands are sent asynchronously,
marking pending state after `_write` completes can overwrite an early device
acknowledgment that arrived during transmission. Setting pending state prior to wire
write and checking `_telemetry.stopConfirmed` prevents clearing confirmed status.
3. **Test Assertion Bypass (`test-assertion-bypass`):** Unit and widget test suites
occasionally wrap crucial assertions or actuation steps inside conditional guards
(e.g., `if (condition) { expect(...); }` or `if (!isPlaceholderGated) { ... }`).
When conditions evaluate to false, tests report green while silently skipping
assertion coverage altogether.
4. **Quality Gate Dependency Preflight (`quality-gate-preflight-dependency`):** CI/CD
and release gate scripts executing unittest discovery or external linters without
upfront verification of required runtime packages fail mid-pipeline or silently omit
discovery tests when dependencies are missing.
5. **Redundant JSON Decoding (`redundant-json-decode`):** Route guards and navigation
interceptors that evaluate stored entities often invoke separate validator and lookup
helpers that both decode the identical raw string. Decoding once with fallback and
inspecting parsed models directly eliminates duplicate parsing overhead.
Analysis must track decodes across consecutive statements within a block (halting on
reassignments like `??=`), distinguish mutually exclusive branches using delimiter-aware
ternary nesting so map literals (`{'k': v}`) are not mistaken for ternary arms, verify
payload argument names and aliases, and scope reporting to touched diff lines to avoid
flagging unchanged base-branch code.
6. **Remediation Agent Operating Safeguards (`ai_review_agent`):** Review remediation
agents must run `review` from the target checkout without unsupported flags (`--path`),
mandate resolving upstream base repositories and fetching non-empty `MERGE_BASE` SHAs
before invoking `review`, verify clean staging indexes before committing, and resolve
fork PR remotes via `gh pr view` to avoid pushing to base repositories.

**Prevention:**
- Enforce that hardware state machines publish pending stop state prior to transmission,
  keep `stopConfirmed: false`, and preserve early acknowledgments on write completion.
- Gate output control buttons and actuation methods on verified protocol state
  (`isConnected && isProtocolVerified`) rather than raw transport connectivity alone.
- Disallow conditional `if` blocks wrapping assertions or action dispatches in test files.
- Ensure all quality gate shell scripts execute preflight checks for required dependencies
  before running unit tests or linters.
- Decode raw JSON payloads once in route guards and inspect the resulting collection.
- Ensure automated remediation workflows verify workspace cleanliness, compute valid merge
  bases, and target remotes safely.
