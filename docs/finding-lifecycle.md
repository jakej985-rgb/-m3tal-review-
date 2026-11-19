# Finding Lifecycle, Baselines & Review History

## Overview

The `m3tal-review` lifecycle engine tracks defect findings across runs, branches, commits, and
baselines. It provides stable finding identity, heuristic similarity matching across code shifts,
and deterministic lifecycle transitions.

## Lifecycle States

Every reported finding in an active review run is categorized into one of six lifecycle states:

1. **`new`**: Newly detected finding that did not exist in the baseline manifest.
2. **`unchanged`**: Exact match with a baseline record (identical fingerprint and position).
3. **`changed`**: Matched against baseline through heuristic similarity (e.g. lines shifted or
   code was reformatted, but underlying defect remains).
4. **`severity_changed`**: The finding exists in the baseline, but its severity score shifted
   (e.g. upgraded from `medium` to `critical`).
5. **`resolved`**: Finding was present in the baseline but is no longer detected in the current run.
6. **`reintroduced`**: Finding was previously marked resolved in review history, but has resurfaced
   in the active codebase.

## Stable Identity & Similarity Matching

To avoid false `new` findings caused by benign edits:
- **`MatchExact`**: Cryptographic fingerprint match on rule, file path, and normalized statement.
- **`MatchHeuristic`**: Token-set Jaccard similarity and semantic function anchors correlate findings
  across line movement (up to 25 lines) and whitespace reformatting. All similarity correlations
  are explicitly labeled as `heuristic`.

## Baseline Manifests & Guarded Storage

Baseline files (`BaselineManifest`) store findings along with commit metadata and cryptographic
integrity hashes:
- **Integrity Validation**: Any manual tampering or corruption of the baseline file is caught by
  comparing the SHA256 integrity hash, causing the engine to fail safely.
- **Guarded Writes**: Overwriting an existing baseline requires explicit opt-in
  (`--update-baseline`), preventing accidental clobbering of regression baselines.
- **Atomic Commits**: Baselines are written through temporary files and renamed atomically.
