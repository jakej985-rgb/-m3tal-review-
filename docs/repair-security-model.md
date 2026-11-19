# M3TAL Review — Repair Safety & Security Model

## Overview

The `m3tal-review repair` subsystem is designed to propose and apply remediations without ever allowing
untrusted proposals or malicious repository configurations to modify files outside the repository root.

---

## 1. Threat Model & Invariants

1. **Root Containment**: No repair proposal can read, write, or truncate any path outside the verified
   repository root (`repoRoot`).
2. **Explicit User Approval**: Automated remediation never applies changes directly without an explicit
   confirmation callback or flag.
3. **Immutability of Proposals**: Proposals passed to approval handlers are defensive copies; post-approval
   verification ensures that bytes written to disk strictly match the verified proposal content.
4. **Symlink Boundary Integrity**:
   - Chained symlinks are fully evaluated (`filepath.EvalSymlinks`) to verify their canonical destination
     lies within `repoRoot`.
   - Escaping symlinks are rejected during boundary validation.
   - Contained symlinks are followed to their canonical internal target during write; the symlink itself
     is preserved rather than overwritten by a regular file.
5. **TOCTOU Resistance**:
   - Path containment is re-checked at write time in `ApplyProposalToFile` using `os.Lstat` and
     `filepath.EvalSymlinks`.
   - If a file is concurrently replaced with an escaping symlink before write, the write is aborted.
6. **Atomic & Durable Writes**:
   - Writes use temporary files in the same directory (`.m3tal-repair-*`), fsync (`file.Sync()`), and
     atomic rename (`os.Rename`).
   - Existing file permissions (`os.FileMode.Perm()`) are preserved; parent directories are created `0755`.
   - On write or sync failure, temporary files are cleanly removed without modifying the destination.

---

## 2. Platform-Specific Mitigations

- **macOS / BSD (`/var` -> `/private/var`)**: Root paths and targets are canonicalized via
  `resolveExistingPath` so aliased system directories do not trigger false-positive escape errors.
- **Windows (NTFS Reparse Points & 8.3 Names)**:
  - Canonicalization expands short names before relative path checks.
  - On Windows, `os.Rename` handles transient file-lock collisions with bounded exponential backoff retries.
  - Windows junction points and reparse tags are evaluated using standard symlink containment logic.
- **Linux (Worktrees & Namespaces)**:
  - Sandboxes isolate git worktrees; escaping symlinks created by `git worktree add` are purged before
    sandbox test runs.

---

## 3. Verification Evidence

The test suite in `internal/repair/adversarial_test.go` exercises:
- Multi-hop chained symlinks (contained vs escaping).
- Dangling symlinks (missing internal vs external targets).
- Concurrent symlink swap (TOCTOU race protection).
- Atomic write failure cleanup (leaving target file unmodified).
- Concurrent repairs in shared directories without race conditions.
