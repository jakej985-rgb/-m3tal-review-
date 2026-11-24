# Security & Maintainability Audit: M3tal-core

- **Audit Date:** November 6, 2026
- **Audited Repository:** `/home/m3tal/apps/M3tal-core` (`github.com/jakej985-rgb/m3tal-core`)
- **Audit Tool:** `m3tal-review` (Local Deterministic Review & Audit CLI)
- **Report ID:** `359ab211bf95aa74`
- **Execution Scope:** Full Working-Tree Static & Heuristic Audit

---

## 1. Executive Summary

A full repository audit of `M3tal-core` was performed using `m3tal-review`. The scan evaluated Go API handlers,
event streams, GUI client components, packaging scripts, and GitHub Actions workflows.

| Severity | Count | Primary Drivers | Action Required |
| :--- | :---: | :--- | :---: |
| **Critical** | **2** | Embedded git credentials in CI, `.env.example` pattern | **Urgent** |
| **High** | **33** | WebSocket origin bypass, web storage tokens, JSX, vendor heuristics | **High** |
| **Medium** | **24** | Timing-unsafe compare, missing timeouts, unpinned CI actions | **Medium** |
| **Low** | **3,076** | Code slop: line length (>120), trailing whitespace, deep nesting | Low |
| **Unanalyzed** | **14** | Shell scripts (`.sh`) and archive packages | Informational |

---

## 2. Critical & High-Priority Security Findings

### 2.1 Cross-Site WebSocket Hijacking Risk (CSWSH)
- **File:** [`api/websockets.go:15-18`](file:///home/m3tal/apps/M3tal-core/api/websockets.go#L15-L18)
- **Rule:** `websocket-origin` (High)
- **Vulnerability:**
  ```go
  var upgrader = websocket.Upgrader{
      ReadBufferSize:  1024,
      WriteBufferSize: 1024,
      CheckOrigin: func(r *http.Request) bool {
          return true
      },
  }
  ```
- **Risk:** The WebSocket upgrader unconditionally accepts connections from any origin. If a user visits a
  malicious website while logged into `M3tal-core`, the third-party website can establish a WebSocket connection
  and receive real-time system event streams (`GlobalEventBus`).
- **Remediation:** Validate that `r.Header.Get("Origin")` matches the configured host origin or local interface.

---

### 2.2 Embedded Credentials in Git Remote URL
- **File:**
  [`push-m3tal-api.yml:32`](file:///home/m3tal/apps/M3tal-core/.github/workflows/push-m3tal-api.yml#L32)
- **Rule:** `secret-material` (Critical)
- **Vulnerability:**
  ```bash
  # Insecure: access token interpolated directly into remote URL
  git remote add api https://TOKEN@github.com/jakej985-rgb/m3tal-api.git
  ```
- **Risk:** Passing sensitive access tokens directly within the URL string persists the secret in git
  configuration logs (`.git/config`), git process execution tables (`ps`), and runner console output on error.
- **Remediation:** Pass the token via an HTTP header configuration instead of embedding it into the remote URL:
  ```bash
  git config extraheader "AUTHORIZATION: basic $(echo -n x-access-token:${TOKEN} | base64)"
  ```

---

### 2.3 Timing-Unsafe Secret Comparison
- **File:** [`api/handlers.go:52`](file:///home/m3tal/apps/M3tal-core/api/handlers.go#L52)
- **Rule:** `timing-unsafe-compare` (Medium)
- **Vulnerability:**
  ```go
  if s.APIToken != "" && token == s.APIToken {
      return true
  }
  ```
- **Risk:** Using standard string `==` equality performs early-exit byte comparison, introducing timing
  side-channels that can allow attackers to infer valid API token characters by measuring network latency.
- **Remediation:** Use constant-time comparison:
  ```go
  if s.APIToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.APIToken)) == 1 {
      return true
  }
  ```

---

### 2.4 Sensitive Authentication Token in Web Storage (XSS Sinks)
- **File:** [`gui/src/api.js:15-17`](file:///home/m3tal/apps/M3tal-core/gui/src/api.js#L15-L17)
- **Rule:** `web-storage-secrets` (High)
- **Vulnerability:**
  ```javascript
  export const setToken = (token) => {
    localStorage.setItem('m3tal_token', token);
  };
  ```
- **Risk:** Storing authorization tokens in `localStorage` makes them directly accessible to JavaScript.
  Any Cross-Site Scripting (XSS) vulnerability or compromised npm package can exfiltrate the token.
- **Remediation:** Migrate authentication tokens to HTTP-only, secure, SameSite cookies or maintain tokens
  in in-memory closures with short-lived session refresh.

---

### 2.5 HTTP Server Without Timeout Protection (Slowloris)
- **File:** [`api/server.go:248`](file:///home/m3tal/apps/M3tal-core/api/server.go#L248)
- **Rule:** `server-timeouts` (Medium)
- **Vulnerability:**
  ```go
  return http.ListenAndServe(":"+port, r)
  ```
- **Risk:** `http.ListenAndServe` initializes an `http.Server` with default zero-duration timeouts. Attackers
  can hold TCP connections open indefinitely with partial requests (Slowloris attack), exhausting file descriptors.
- **Remediation:** Explicitly configure an `http.Server` with timeouts:
  ```go
  srv := &http.Server{
      Addr:              ":" + port,
      Handler:           r,
      ReadHeaderTimeout: 5 * time.Second,
      ReadTimeout:       15 * time.Second,
      WriteTimeout:      30 * time.Second,
      IdleTimeout:       60 * time.Second,
  }
  return srv.ListenAndServe()
  ```

---

## 3. Heuristic Noise & Scanner Analysis Insights

The audit uncovered several tool-tuning and environment patterns:

### 3.1 JSX Grammar Tripping JavaScript Scanner
- **Files:** `gui/src/**/*.jsx` (12 files, including `App.jsx`, `Dashboard.jsx`, `Plugins.jsx`)
- **Finding:** `code-slop-analysis-error: Could not safely analyze JavaScript structure: unterminated literal`
- **Cause:** `m3tal-review` treats `.jsx` files under its JavaScript brace parser. JSX markup syntax (`<div>`)
  introduces angle brackets that the current JS scanner evaluates as loose comparison operators or unclosed tokens.
- **Recommendation for `m3tal-review`:** Enhance JSX scanner to ignore angle-bracket tags during analysis.

### 3.2 Committed `node_modules` Directories
- **Paths:** `node_modules/` (root) and `.github/scripts/node_modules/`
- **Impact:** 6 high-severity and 2 medium-severity findings (`dynamic-code-loading`, `hardcoded-credential` on
  `MAX_TOKENS`, `Math.random` in `@google/generative-ai`) originate inside checked-in vendor modules.
- **Recommendation:** Ensure dependency directories are excluded via `.gitignore` or audited with package scanners.

### 3.3 `.env.example` False Positive
- **File:** `.env.example:1`
- **Finding:** `secret-file: File looks like committed secret material`
- **Cause:** The `secret-file` heuristic matches `(?:\.env(?:\.|$)...)`. Template configuration files such as
  `.env.example` or `.env.template` should be explicitly allowlisted in `m3tal-review`.

---

## 4. Unanalyzed Files (Audit Coverage Gap)

The audit flagged 14 tracked files as unanalyzed:
- `build.sh`, `install.sh`
- `scripts/*.sh` (`audit-plugin.sh`, `build-deb.sh`, `build-go.sh`, `bump-version.sh`, `postinstall.sh`, etc.)
- `dists/stable/main/binary-amd64/Packages.gz`

Shell scripts currently trigger the fallback source classifier. Adding a dedicated shell analyzer or marking
packaging scripts in `.m3tal-review-ignore` will ensure 100% complete audit runs.

---

## 5. Prioritized Remediation Roadmap for M3tal-core

1. **Fix CSWSH in [`api/websockets.go`](file:///home/m3tal/apps/M3tal-core/api/websockets.go):**
   Replace `CheckOrigin: return true` with an origin allowlist.
2. **Mitigate Timing Attack in [`api/handlers.go`](file:///home/m3tal/apps/M3tal-core/api/handlers.go):**
   Use `subtle.ConstantTimeCompare` on API tokens.
3. **Add HTTP Timeouts in [`api/server.go`](file:///home/m3tal/apps/M3tal-core/api/server.go):**
   Instantiate `&http.Server` with explicit read/write timeouts.
4. **Clean Git Remote Secrets in Push Workflow:**
   In [`push-m3tal-api.yml`](file:///home/m3tal/apps/M3tal-core/.github/workflows/push-m3tal-api.yml),
   use header authentication instead of URL embedding.
5. **Ignore `node_modules` in Audits:**
   Configure `.m3tal-review-ignore` to exclude third-party vendor directories from local code quality scans.
