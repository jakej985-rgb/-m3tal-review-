// Package authproto implements modeled checking of authentication and
// cryptographic protocol properties.
//
// A contract (schema version "authproto/1", see
// docs/authproto-contracts.md) declares an authentication or
// key-establishment transcript: ordered messages between parties, the
// role of each field (nonce, challenge, proof, session identifier,
// key), and the *declared* properties that make the construction
// secure — freshness, single-use enforcement, transcript coverage
// (what the proof commits to), the verification construction, and
// key-derivation inputs.
//
// The analyzer is a pragmatic modeled checker, not a theorem prover.
// It answers one question per modeled property: "given these
// declarations, does the transcript admit a named attacker
// capability?" It never claims a cryptographic proof, and it never
// upgrades a declared property into a verified one.
//
// Attacker model (fixed, documented in docs/authproto-contracts.md):
// a Dolev-Yao-style network attacker who can observe, modify, drop,
// inject, and replay protocol messages, and who has unbounded offline
// computation. The attacker cannot break assumed cryptographic
// primitives, cannot compromise endpoints, and cannot forge proofs
// except through the weaknesses the checks look for.
//
// Modeled checks:
//
//   - authproto.offline-guessing: a proof (or derived key) whose
//     verification/derivation runs through low-entropy password
//     material lets a passive observer test candidates offline.
//   - authproto.replay: a proof that commits to no fresh,
//     single-use, verifier-issued challenge can be replayed.
//   - authproto.transcript-binding: a proof that does not commit to
//     every nonce/challenge/session field may verify across session
//     contexts.
//   - authproto.nonce-uniqueness: nonces/challenges declared non-fresh
//     repeat across sessions; fresh claims bound to source are checked
//     for math/rand (predictable) vs crypto/rand (CSPRNG) use.
//   - authproto.weak-randomness (source-derived): a source-bound nonce
//     generator reaching math/rand undermines the freshness claim.
//   - authproto.unmodeled: constructions outside the modeled set are
//     reported StatusUnverified — never silently approved.
//
// Honesty guarantees:
//
//   - Model findings are StatusPotential: the declared model may
//     diverge from the implementation, and conformance is unverified.
//   - Unmodeled constructions produce StatusUnverified findings.
//   - No finding is ever StatusProven: pattern and model matching
//     cannot prove cryptographic properties.
//   - Every finding names the attacker capabilities it enables, the
//     assumptions it relies on, and what was NOT proven.
package authproto
