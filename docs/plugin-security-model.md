# M3TAL Review — Plugin Security & Isolation Model

## Overview

The `m3tal-review` plugin subsystem allows external analyzer binaries to run alongside native analyzers.
To protect developer systems, repository-local and third-party plugins execute under strict security,
resource, and isolation controls.

---

## 1. Process Isolation & Termination

1. **Process Group Containment (`preparePluginCmd`)**:
   - On Unix systems, subprocess plugins are spawned with `Setpgid: true`.
   - On timeout or caller cancellation, `cmd.Cancel` delivers `SIGKILL` to the negative process group ID (`-pid`),
     ensuring that background worker children, child forks, and daemons are terminated rather than leaked.
   - On Windows, `cmd.Cancel` executes process termination directly.
2. **Execution Time Limits**:
   - Subprocess execution is strictly bounded by per-plugin timeouts (`DefaultPluginTimeout = 30s`,
     capped at `MaxPluginTimeout = 5m`).
   - Timed-out executions produce explicit `failed` check results and `confidence` findings.
3. **Memory & Output Capping**:
   - Plugin standard output and standard error are captured through fixed-size buffers (`cappedBuffer`)
     limited to 1 MiB (`maxPluginOutput`).
   - Unbounded output can never exhaust host memory.
4. **Environment Sanitization**:
   - Sensitive environment variables (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*AUTH*`, `*KEY*`, and `M3TAL_*`)
     are stripped from the subprocess environment before execution, preventing credential leakage to
     third-party tools.
5. **Untrusted Repository Plugins**:
   - Plugins located inside the analyzed repository (`.m3tal-review/plugins`) are treated as untrusted.
   - They are never executed without both `--allow-repo-plugins` AND explicit SHA-256 allowlisting in the user
     configuration (`plugin_allow_sha256`).
   - Unlisted repository binaries are rejected without executing even `--manifest` probing.
