## 2026-11-23 - Unverified Hardware Actuation and Test Assertion Bypass Rules

**Learning:** Four recurring classes of silent failure escaped AST inspections:
1. **Unverified Hardware Actuation (`unverified-hardware-actuation`):** Bridges and
transports transmitting hardware actuator commands (e.g. `PIN:13:OUTPUT`, `LED:ON`,
or emergency stop sequences) frequently assumed actuation success upon wire
transmission rather than awaiting explicit device acknowledgments (`ACK:`, `PONG:`,
`PIN13:LOW`). In safety-critical or physical microcontroller environments, an
unacknowledged transmission leaves hardware in an active/dangerous state while local
state mirrors a false safe state. Furthermore, sending actuator commands before
protocol handshake negotiation exposes unverified firmware to corrupted states.
2. **Test Assertion Bypass (`test-assertion-bypass`):** Unit and widget test suites
occasionally wrap crucial assertions or actuation steps inside conditional guards
(e.g., `if (condition) { expect(...); }` or `if (!isPlaceholderGated) { ... }`).
When conditions evaluate to false, tests report green while silently skipping
assertion coverage altogether.
3. **Quality Gate Dependency Preflight (`quality-gate-preflight-dependency`):** CI/CD
and release gate scripts executing unittest discovery or external linters without
upfront verification of required runtime packages fail mid-pipeline or silently omit
discovery tests when dependencies are missing.
4. **Remediation Agent Operating Safeguards (`ai_review_agent`):** Review remediation
agents must run `review` from the target checkout without unsupported flags (`--path`),
verify clean staging indexes before committing, and resolve fork PR remotes via
`gh pr view` to avoid pushing to base repositories.

**Prevention:**
- Enforce that hardware state machines keep `stopConfirmed: false` and disable actuator
  command dispatch until device response frames (`ACK:STOP`, `PIN13:LOW`, etc.) or
  verified protocol handshakes are observed.
- Gate output control buttons and actuation methods on verified protocol state
  (`isConnected && isProtocolVerified`) rather than raw transport connectivity alone.
- Disallow conditional `if` blocks wrapping assertions or action dispatches in test files.
- Ensure all quality gate shell scripts execute preflight checks for required dependencies
  before running unit tests or linters.
- Ensure automated remediation workflows verify workspace cleanliness and target remotes.
