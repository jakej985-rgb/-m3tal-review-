// Package protocol implements versioned protocol contracts and
// cross-version compatibility analysis.
//
// A protocol contract (schema version "protocol/1", see
// docs/protocol-contracts.md) describes the wire surface of an API in
// a small, language-neutral YAML/JSON format: requests, responses,
// headers, authentication, pairing, and capability negotiation. The
// format is deliberately contract-vs-contract: deployed versions are
// represented by checked-in contract snapshots, and the analyzer
// compares two snapshots element-by-element. It never pretends a
// single checkout knows which versions are deployed — missing
// historical snapshots are reported as diagnostics.
//
// Compare produces analysis.Finding values for removed/renamed
// fields, type changes, changed defaults, requiredness changes,
// authentication-behavior changes, and capability drift. Each change
// records the compatibility directions it affects
// (old-client/new-server and/or new-client/old-server) so the
// compatibility matrix can be evaluated per direction. Structural
// incompatibilities (removals, renames, type and requiredness
// changes) are reported directly; semantic changes (defaults, auth
// behavior, capability values) require an explicit assertion in the
// contract's compat block before they are considered acknowledged.
// Intentional breaking changes and semantic assertions are declared
// per-element and suppress only their own finding — never unrelated
// ones.
//
// EvaluateMatrix compares every pair of supplied version snapshots
// once and fills a client-version x server-version compatibility
// matrix for both directions.
package protocol
