# m3tal-review — 1000 improvement ideas

Backlog brainstorm grouped by area. Items are one-line intents; feasibility
and priority should be evaluated per item before implementation. Conventions
from `docs/improvement-plan.md` still apply: deterministic rules, added-line
attribution, path-safety for untrusted repos, tests + README per detector.

## A. Injection & execution — web/server (1–50)

1. GraphQL injection: queries/mutations built with string concat or f-strings.
2. NoSQL injection: `{"$where": ...}`, `find({"$gt": user})` with user input.
3. Template injection beyond SSTI: `eval`-like template helpers, `Template()` in Go html/template with dynamic template names.
4. Email header injection: `Subject:`/`To:` built from user input without CRLF stripping.
5. CSV/Excel formula injection: cells starting `=`, `+`, `-`, `@` exported to spreadsheets.
6. Path canonicalization bypass: `filepath.Clean` result re-checked against root, not the raw input.
7. `http.ServeFile`/`Static` with `..` after cleaning — flag `path.Clean` + join patterns missing `IsLocal`.
8. Open redirect via `Referer`/`Origin` headers trusted as targets.
9. Host header injection: `r.Host` used in password-reset links or redirects.
10. Cache poisoning: unkeyed user input in cache keys (`Vary` missing).
11. Web cache deception: authenticated responses cached due to missing `Cache-Control: private`.
12. HTTP request smuggling hints: duplicate `Content-Length`/`Transfer-Encoding` handling code.
13. Parameter pollution: duplicate query params where last-wins assumed.
14. `json.Decoder.DisallowUnknownFields` missing on strict API payloads.
15. Mass-assignment via ORM `Updates(struct)` / `Save()` of request-bound structs.
16. GraphQL depth/complexity limits absent on public endpoints.
17. File upload: missing extension/MIME allowlist, path from `filename` header.
18. ImageMagick/ffmpeg command built from upload metadata.
19. XXE variant: `XMLStreamReader`, `Unmarshaller`, `jaxb`, `simplexml_load_string` without `libxml_disable_entity_loader`.
20. SSRF via redirect-following clients (`CheckRedirect` unrestricted, axios `maxRedirects: 0` absent).
21. SSRF via DNS rebinding: URL validated then re-resolved at fetch time.
22. SSRF via IPv6/decimal/octal IP literals bypassing host allowlists.
23. SSRF via `file://`, `gopher://`, `dict://` schemes not blocked.
24. Blind SSRF detection: any outbound HTTP call in request handlers, even literal URLs on private ranges.
25. Command injection via environment variables (`os.environ` into exec args).
26. Command injection via filenames passed to shell commands.
27. `child_process.execFile` with shell metachars in args array.
28. Template literal injection into `eval`/`Function` in JS.
29. `vm.runInNewContext`/`node:vm` with user code.
30. `pickle`/`marshal`/`shelve`/`dill` already covered — extend to `cloudpickle`, `joblib.load`.
31. `yaml.load` without Loader in Ruby/PHP (`YAML.load`, `yaml.safe_load` absent).
32. Java `ObjectInputStream.readObject` on untrusted bytes.
33. .NET `BinaryFormatter`, `LosFormatter`, `ObjectStateFormatter`.
34. PHP `unserialize` on cookies/session data.
35. Deserialization gadget chains: `commons-collections`, `fastjson` `@type`, Jackson default typing.
36. `fastjson`/`jackson` polymorphic deserialization flags.
37. Log4Shell-style JNDI: `InitialContext.lookup`, `${jndi:` patterns in logs/config.
38. XPath injection via concatenated predicates (covered partially — extend to `document()`).
39. LDAP injection in bind DN construction.
40. SMTP/header injection in mail libraries.
41. Regex DoS (ReDoS): nested quantifiers `(a+)+`, `(a|a)*` in user-facing patterns.
42. Polynomial backtracking in glob/pattern matchers on user input.
43. `new RegExp(userInput)` unescaped.
44. eval-in-config: `eval`/`exec`/`compile` in settings files.
45. Dynamic require/import of user-controlled path (`require(req.params.x)`).
46. `importlib.import_module(user)` / `__import__(user)`.
47. Plugin/extension loading from writable dirs.
48. Deserialization of `pickle` in Celery/RQ task payloads.
49. `subprocess` with `shell=True` equivalent in Go (`exec.Command("sh","-c")`).
50. Server-side include / template `include` of user path.

## B. Secrets, crypto & auth (51–100)

51. AWS secret key pattern `AKIA`/`ASIA` already covered — add `aws_secret_access_key` assignment forms.
52. GCP service-account JSON blobs (`"type": "service_account"`).
53. Azure connection strings (`DefaultEndpointsProtocol=`, `AccountKey=`).
54. Slack webhook URLs `hooks.slack.com/services/T…/B…/…`.
55. Stripe live keys `sk_live_`/`rk_live_` (vs `sk_test_`).
56. SendGrid/Twilio/Mailgun API key formats.
57. Private keys without PEM armor (`BEGIN OPENSSH PRIVATE KEY`, `BEGIN RSA/EC/DSA`).
58. SSH authorized_keys material committed.
59. Kubernetes Secret/TLS manifests with `data:`/`stringData:` literals.
60. Terraform state files or `.tfvars` with secrets.
61. Vault tokens `hvs.`/`s.` prefixes, Consul ACL tokens.
62. Database URLs with embedded passwords (`postgres://user:pass@`).
63. `mongodb://`, `redis://`, `amqp://` URLs with credentials.
64. JWT hardcoded signing secrets (HS256 weak secrets <32 bytes).
65. JWT `kid` injection / `jku`/`x5u` header trust.
66. Session cookie without `Secure`/`HttpOnly`/`SameSite` (server-side set-cookie audit).
67. OAuth `state` parameter missing on login flows.
68. OAuth redirect_uri not pinned/validated.
69. PKCE absent on public OAuth clients.
70. Password reset tokens: non-expiring, non-single-use, leaked in URL/logs.
71. MFA bypass: `otp`/`totp` verification skipped on error paths.
72. Timing-safe compare for API keys/tokens (extend beyond passwords).
73. bcrypt cost <10, PBKDF2 iterations <100k, scrypt N<2^14.
74. SHA-256/MD5 used for password hashing.
75. Hardcoded salts/IVs/nonces.
76. ECB mode in any language.
77. RSA PKCS#1 v1.5 encryption (`RSAES-PKCS1-v1_5` for encryption, not signatures).
78. RSA key <2048 bits.
79. ECDSA nonce reuse / `ecdsa.Sign` without random nonce.
80. X25519/Ed25519 misuse: signing with encryption keys.
81. `math/rand` seeded with time for tokens (narrower than general rand).
82. `uuid` v1/time-based IDs used as unguessable tokens.
83. Sequential/guessable IDs exposed as authz handles.
84. JWT `exp`/`nbf`/`iat` not validated.
85. `none` algorithm, algorithm confusion RS256→HS256.
86. Refresh tokens without rotation/reuse detection.
87. API keys in URLs (`?api_key=`, `?key=`, `?token=`).
88. Credentials in `Authorization` header logged.
89. Basic auth over non-TLS endpoints.
90. `eval` of license keys / license bypass checks.
91. Feature-flag/license checks client-side only.
92. `debug=true`/`admin=true` params enabling privileged paths.
93. Hardcoded backdoor accounts (`if user=="admin" && pass=="..."`).
94. `NOPASSWD` sudoers, `chmod u+s` setuid bits in scripts.
95. World-readable private keys (`0644` on `*.pem`).
96. TLS: `SSLv3`, `TLS1.0/1.1` allowed, weak cipher suites.
97. Certificate pinning absent on mobile/desktop clients.
98. `Strict-Transport-Security` missing on HTTPS apps.
99. Clickjacking: `X-Frame-Options`/`frame-ancestors` absent.
100. CSRF tokens missing on state-changing endpoints (framework-aware heuristic).

## C. Web/client-side (101–150)

101. `eval`/`new Function` in client JS (partially covered — extend sinks).
102. `setTimeout(string)`/`setInterval(string)` code execution.
103. `document.write`/`outerHTML`/`insertAdjacentHTML` (covered) — add `Range.createContextualFragment` all variants.
104. jQuery `.html(userData)`, `.append(userHtml)`.
105. `dangerouslySetInnerHTML` with `__html` from props/state.
106. Vue `v-html`, Angular `[innerHTML]`, Svelte `{@html}`.
107. Handlebars `{{{triple}}}`, Mustache `{{=<% %>=}}` delimiters.
108. DOM clobbering: `id`/`name` attributes colliding with globals.
109. `postMessage` targetOrigin `"*"` on sensitive data.
110. `window.opener` retained after `window.open` (reverse tabnabbing).
111. `localStorage`/`sessionStorage`/`IndexedDB`/`document.cookie` for tokens (storage covered — extend to IndexedDB/caches).
112. Service worker caching authenticated responses.
113. `navigator.sendBeacon`/`fetch` leaking data cross-origin.
114. Third-party scripts without SRI (`integrity=` missing on CDN `<script>`).
115. `iframe srcdoc`/`src=javascript:` sinks.
116. `location.hash`/`location.search` parsed into DOM/sinks.
117. Client-side route guards as sole authz (server must re-check).
118. `innerText` vs `textContent` confusion leading to HTML injection.
119. Prototype pollution gadgets: `_.merge`, `$.extend(true)`, `lodash.set` paths.
120. `Object.assign` onto `this`/`config` from request.
121. `URL.createObjectURL` + `innerHTML` blob XSS.
122. WebSocket `onmessage` rendering without sanitization.
123. `EventSource`/SSE data injected into DOM.
124. `FileReader.readAsText` → `innerHTML`.
125. `DOMParser.parseFromString` → adopted nodes.
126. `CSS` injection: `style` attribute/`innerHTML` with user CSS (`expression()`, `url(javascript:)`).
127. `postMessage` listeners without `event.source` check.
128. Cross-window `localStorage` access assumptions.
129. `BroadcastChannel`/`SharedWorker` trusting messages.
130. `history.pushState` open redirect via crafted URLs.
131. Reflected params echoed into `<script>`/`on*` attributes.
132. JSONP endpoints with user callback names.
133. CORS `Access-Control-Allow-Origin` reflected request origin + credentials.
134. CORS wildcard subdomain regex (`*.example.com` matching `evil-example.com`).
135. `Vary: Origin` missing causing cache poisoning.
136. Mixed content: `http://` resources on HTTPS pages.
137. `target="_blank"` without `rel="noopener"`.
138. Sensitive data in `window.name`/`document.referrer` leaks.
139. Autofill on password/CC fields (`autocomplete` misuse).
140. `input[type=password]` values logged/echoed.
141. Clipboard API writing sensitive data.
142. `navigator.credentials`/WebAuthn attestation misuse.
143. Feature detection leaking browser fingerprints to trackers (privacy, low).
144. `console.log` of objects containing tokens (client-side secret leakage).
145. Source maps exposing secrets/comments in production builds.
146. Hardcoded API keys in client bundles (acceptable for public keys — flag private-looking ones only).
147. `wasm`/`asm.js` obfuscation hiding exfil logic.
148. Browser extension content scripts with `eval`.
149. `chrome.runtime.sendMessage` without origin checks in extensions.
150. `window.name` persistence of sensitive data across origins.

## D. Infrastructure, IaC & cloud (151–200)

151. Terraform: `0.0.0.0/0` ingress/egress on sensitive ports.
152. Terraform: public S3 buckets (`acl = "public-read"`, `block_public_acls = false`).
153. Terraform: unencrypted storage (`encrypted = false`, missing `server_side_encryption`).
154. Terraform: hardcoded secrets in `.tf`/`user_data`/`templatefile`.
155. Terraform: `latest` AMI/provider versions unpinned.
156. CloudFormation: `AWS::IAM::Policy` with `"Action": "*"`/`"Resource": "*"`.
157. IAM: wildcard actions/resources, missing conditions.
158. IAM: `iam:PassRole` without resource constraints.
159. Security groups: SSH/RDP open to `0.0.0.0/0`.
160. K8s: pods without `runAsNonRoot`, `readOnlyRootFilesystem`.
161. K8s: `privileged: true`, `allowPrivilegeEscalation: true`, missing `drop ALL` caps.
162. K8s: host namespaces (`hostPID`, `hostNetwork`, `hostIPC`).
163. K8s: hostPath mounts, docker.sock mounts.
164. K8s: `automountServiceAccountToken` not disabled where unneeded.
165. K8s: secrets in env vars instead of mounted volumes (visible in describe).
166. K8s: missing NetworkPolicies (default-allow posture).
167. K8s: `latest` image tags, missing `imagePullPolicy`.
168. K8s: missing resource limits/requests (DoS vector).
169. K8s: missing liveness/readiness probes on critical services.
170. K8s: `emptyDir`/`hostPath` for secrets persistence.
171. K8s: RBAC roles with `*` verbs/resources.
172. K8s: `secrets` type `kubernetes.io/tls` with weak keys.
173. Dockerfile: running as root (no `USER` directive).
174. Dockerfile: `ADD` remote/git (covered), `--chmod` wide perms.
175. Dockerfile: secrets in `ARG`/`ENV` baked into layers.
176. Dockerfile: `apt-get`/`apk` without version pins or `--no-install-recommends`.
177. Dockerfile: `curl|sh` installers (covered) — extend to `wget`, `bash <(curl)`.
178. Docker-compose: `privileged`, `network_mode: host`, `cap_add: ALL`.
179. Compose: hardcoded passwords in `environment:`.
180. Compose: `image: latest` unpinned.
181. Helm: `{{ .Values }}` templates rendering secrets into manifests.
182. GitHub Actions: `pull_request_target` (covered) — add `workflow_run` abuse, `issue_comment` triggers on untrusted text.
183. Actions: `${{ secrets.* }}` in `if:` conditions or passed to untrusted actions.
184. Actions: `actions/checkout` of `github.event.pull_request.head.sha` under target trigger.
185. Actions: missing `permissions:` block (covered partially) — detect explicit `write-all`.
186. Actions: third-party actions not SHA-pinned (covered) — detect `docker://` actions unpinned.
187. Actions: `GITHUB_TOKEN` permissions escalation via `permissions: write-all`.
188. Actions: artifact/cache poisoning across workflows.
189. GitLab CI: unpinned images, `only: merge_requests` script injection.
190. CircleCI: context secrets echoed, orbs unpinned.
191. Jenkins: `parameters`/`${BUILD_USER}` script injection, unpinned plugins.
192. Ansible: `become: yes` with unvalidated vars, `shell:` module use.
193. Puppet/Chef: template injection, unpinned modules.
194. Nomad/Consul/Vault configs: unauthenticated ACLs, `auth` disabled.
195. Serverless: IAM roles with `*` on functions, public function URLs.
196. CDN/WAF: missing security headers config, cache rules on auth paths.
197. DNS: missing DNSSEC, wildcard records on apex, dangling CNAMEs (subdomain takeover).
198. Email: missing SPF/DKIM/DMARC records in IaC.
199. Certificates: self-signed/internal CAs trusted broadly, cert expiry unchecked.
200. Backup: unencrypted backups, backups in same failure domain, no restore tests.

## E. Go correctness (201–250)

201. `errcheck`-style: unchecked `Close()` on write files (not just read).
202. `rows.Err()` after iteration not checked.
203. `json.NewDecoder().Decode` in loop without EOF handling.
204. `sql.Rows` closed but `Err()` unchecked.
205. `http.Response.Body` closed but read error unchecked.
206. `defer` in loop (covered) — also `defer` before error check ordering bugs.
207. `time.After` in loop creating timer leaks — use `time.NewTimer`+Stop.
208. `context.WithCancel`/`WithTimeout` without calling cancel (vet warns — detect manually).
209. Goroutine leak: `go func` sending on unbuffered channel never received.
210. Goroutine leak: `sync.WaitGroup.Add` inside loop with `Done` missing on error paths.
211. `select` with only one case + default = pointless.
212. `for range ch` without close → deadlock on early return.
213. Mutex copied by value (`type T struct { mu sync.Mutex }` passed by value).
214. `sync.Map` misuse: storing pointers then mutating.
215. `atomic` ops on non-64-bit-aligned fields on 32-bit.
216. Slice aliasing bugs: `append` to shared backing array, `s[:n]` retained.
217. `map` concurrent read/write without sync.
218. `recover()` outside deferred func (no-op).
219. `panic` used for control flow in library code.
220. `init()` ordering dependencies between files (implicit).
221. Package-level `var` with `init`-time side effects (network, files).
222. `//go:linkname` usage.
223. `unsafe` pointer arithmetic (covered) — `unsafe.Slice` bounds assumptions.
224. `reflect` heavy paths in hot loops.
225. `interface{}`/`any` type assertions without ok-check in chains.
226. Nil map write panic: `m[k] = v` on nil map literal paths.
227. Nil pointer deref: method on nil receiver not guarded.
228. `defer` capturing loop variable pre-Go1.22 semantics.
229. `range` variable capture in goroutines.
230. Integer overflow: `int` arithmetic on untrusted sizes, `len()` casts.
231. `uint`/`int` conversion truncation on 32-bit.
232. `strconv.Atoi` unchecked (covered) — `ParseInt` bitSize mismatches.
233. `time.Duration` multiplication overflow (`time.Second * n`).
234. `ioutil` deprecated (covered) — `io/ioutil` imports.
235. `interface{}` → `any` modernization.
236. Empty `interface{}` returns losing type safety.
237. `switch` with duplicate case values (compile error — detect in broken builds? skip).
238. Unreachable `default` after exhaustive enum switch.
239. `fallthrough` misuse in type switches.
240. `goto` usage (slop).
241. Label/shadowing confusion.
242. `var x T` then `x = T{}` redundant.
243. `make` with wrong size hints (`make([]T, 0, len)` misuse).
244. Channel direction not constrained in signatures.
245. `select` default masking real blocking bugs.
246. `time.Sleep` (covered) — `time.Tick` in long-running funcs (leaks ticker).
247. `http.Server` without `ReadHeaderTimeout`/`IdleTimeout` (Slowloris).
248. `http.Client` without `Timeout` set.
249. `tls.Config` missing `MinVersion`.
250. `rand.Read` partial reads not looped.

## F. Go security-specific (251–300)

251. `template.HTML()`/`template.JS()`/`template.URL()` wrapping user data (XSS bypass).
252. `html/template` vs `text/template` confusion on HTML output.
253. `json.Unmarshal` into `interface{}` then type-assert chains.
254. `gob`/`msgpack` decode of untrusted data.
255. `net/rpc`/`grpc` without auth interceptors.
256. `pprof` imported in prod binary paths (covered partially).
257. `expvar` publishing sensitive vars.
258. `runtime.SetMutexProfileFraction`/`SetBlockProfileRate` left in prod.
259. `debug.SetGCPercent(-1)`/`debug.FreeOSMemory` misuse.
260. `os/exec` env passthrough leaking secrets to child processes.
261. `syscall.Exec`/`ForkExec` direct usage.
262. `plugin.Open` on user-controlled paths.
263. `net.Listen` on `0.0.0.0` vs localhost in dev tools.
264. `net/http` serving user-provided Content-Type/Content-Disposition.
265. `http.Error` reflecting user input unescaped.
266. `http.Redirect` with user-controlled `url` param (covered partially).
267. `httputil.ReverseProxy` `Director` rewriting without validation.
268. `websocket`/`gorilla` `CheckOrigin` returning true always.
269. `jwt-go` `ParseUnverified` in prod paths.
270. `oauth2` `InsecureSkipVerify`/custom transports.
271. `x/crypto` ssh `InsecureIgnoreHostKey`.
272. TLS client certs: `Certificates` loaded from world-readable paths.
273. mTLS: `ClientAuth: RequireAnyClientCert` too lax.
274. `hmac.Equal` vs `==` on MACs (covered partially — extend to all secret compares).
275. `subtle.ConstantTimeCompare` length leak (returns early on len mismatch).
276. `bcrypt.CompareHashAndPassword` timing on malformed hashes.
277. `scrypt`/`argon2` params in code review range.
278. AES-GCM nonce reuse detection (same nonce literal twice).
279. `cipher.NewGCMWithNonceSize` non-12-byte nonces.
280. ChaCha20-Poly1305 nonce reuse.
281. Key derivation from passwords without salt.
282. Hardcoded encryption keys in source (pattern: 16/24/32-byte literals near `NewCipher`).
283. `rsa.GenerateKey` <2048, `ecdsa.GenerateKey` P-256 minimum.
284. `x509` `InsecureSkipVerify` on `VerifyOptions`.
285. `x509` parsing user certs without chain validation.
286. `pem.Decode` without block-type check.
287. `asn1.Unmarshal` panics on malformed input.
288. `big.Int` `SetBytes` on untrusted length.
289. `compress/gzip`/`flate` zip-bomb ratios unchecked.
290. `io.Copy` without `LimitReader` on untrusted streams.
291. `ioutil.ReadAll`/`io.ReadAll` on untrusted sizes (memory exhaustion).
292. `bufio.Scanner` default 64KB token limit on long lines.
293. `encoding/gob` type confusion.
294. `encoding/xml` entity expansion (covered) — `Decoder.Strict=false` paths.
295. `text/template` on untrusted templates.
296. `sql` string building via `fmt.Sprintf`/`+` (covered) — ` squirrel`/`goqu` misuse.
297. `gorm`/`sqlx` raw query helpers with user input.
298. `ent`/`sqlc` generated query bypass.
299. GraphQL resolvers returning unfiltered fields (IDOR heuristic).
300. gRPC reflection enabled in prod.

## G. Python checks (301–350)

301. `eval`/`exec`/`compile`/`__import__` (covered partially) — `exec` in class bodies, decorators.
302. `pickle`/`marshal`/`shelve`/`dill`/`cloudpickle`/`joblib` (covered partially).
303. `yaml.load` without `SafeLoader` (covered) — `yaml.compose`, `yaml.scan` edge cases.
304. `subprocess` `shell=True` (covered) — `os.popen`, `commands.getoutput`, `pty.spawn`.
305. `os.system` (covered) — `os.spawn*`, `os.exec*`, `commands` module.
306. `input()` in Py2-style or `eval(input())`.
307. `assert` for security checks (covered) — `assert` on authz paths broadly.
308. `except:` bare / `except Exception: pass` (covered partially) — `except BaseException`.
309. `raise e` vs bare `raise` (deferred) — traceback loss.
310. `finally` with `return`/`break`/`continue` (covered).
311. Mutable default args (covered) — class-level mutable attrs (covered) — `self.x = []` shared via class.
312. `global`/`nonlocal` writes (covered global; add nonlocal).
313. `type(x) == T` (covered) — `type(x) is T`, `isinstance` with tuple misuse.
314. `is`/`is not` literals (covered) — `== None`/`!= None` should be `is None`.
315. String formatting SQL (`%`, `.format`, f-strings — covered partially) — `+` concat variants, `text()` raw SQL.
316. `open()` without encoding (locale-dependent).
317. `open()` on user paths without validation (covered partially) — `pathlib.Path` variants.
318. `os.path.join` + user input traversal.
319. `shutil.rmtree`/`os.remove` on user paths.
320. `tempfile` predictable names (`/tmp/` + pid patterns).
321. `pickle` protocol version pinning.
322. `random` for security (covered) — `secrets` module preferred hints.
323. `hashlib.md5`/`sha1` for passwords (covered partially) — unsalted hashes.
324. `crypt` module deprecated usage.
325. `hmac.compare_digest` vs `==` on tokens.
326. JWT `alg=none`/`verify=False` (covered) — `jwt.decode` without `algorithms=`.
327. `requests` `verify=False` (covered) — `urllib3.disable_warnings` globally.
328. `http.client`/`httplib` without TLS context.
329. `socket` without timeout (hang risk).
330. `threading` without locks on shared state.
331. `multiprocessing`/`concurrent` shared mutable state.
332. `signal` handlers doing unsafe work.
333. `atexit`/`__del__` side effects.
334. `__builtins__` manipulation.
335. `getattr`/`setattr`/`hasattr` dynamic dispatch on user input.
336. `importlib` dynamic imports of user paths.
337. `compile()`/`exec()` of user code in sandbox attempts.
338. `code.InteractiveConsole`/`codeop` exposure.
339. Flask `debug=True` in prod paths.
340. Django `DEBUG=True`, `ALLOWED_HOSTS=['*']`.
341. FastAPI/Starlette `CORSMiddleware(allow_origins=['*'], allow_credentials=True)`.
342. `pickle` in Celery tasks/RQ jobs.
343. `marshal`/`shelve` on user files.
344. `configparser`/`json` eval-adjacent parsing.
345. `ast.literal_eval` alternatives missing (safe eval hints).
346. `logging` of passwords/tokens/PII (`logger.info(password)` heuristics).
347. `print` of secrets in CLI tools.
348. Hardcoded credentials in `settings.py`/`config.py`/`secrets.py` filenames (extend secret-file rule to `.py` config names? filename rule covers generic; add `settings.py` only when containing key patterns — skip filename-only).
349. `os.environ` secrets written to logs/files.
350. `subprocess` env inheritance leaking secrets.

## H. JavaScript/TypeScript checks (351–400)

351. `eval`/`new Function` (covered) — `setTimeout`/`setInterval` strings (covered) — `execScript`.
352. `innerHTML`/`outerHTML`/`document.write` (covered) — `insertAdjacentHTML`, `srcdoc`, `createContextualFragment` (covered) — `Range`, `DOMParser` adoption.
353. jQuery `.html()/.append()/.before()/.after()` sinks.
354. React `dangerouslySetInnerHTML` (covered) — `href={javascript:}` in props.
355. Vue `v-html` (covered) — `v-bind:href` javascript: URLs.
356. Angular `[innerHTML]`/`bypassSecurityTrust*` APIs.
357. Svelte `{@html}`.
358. `postMessage` without origin (covered) — `targetOrigin="*"` sends.
359. `localStorage`/`sessionStorage` tokens (covered) — `IndexedDB`, `caches`, `document.cookie` (covered partially).
360. Prototype pollution (covered) — `lodash.merge`/`_.set` path traversal, `__proto__` in JSON.parse reviver.
361. `Object.assign`/`spread` onto privileged objects.
362. `JSON.parse` without schema validation on user data.
363. `RegExp` from user input (ReDoS covered) — `new RegExp` unescaped.
364. `child_process.exec`/`spawn` (covered) — `execFile` arg injection, `shell:true` option.
365. `fs.readFileSync`/`writeFileSync` on user paths (covered partially).
366. Path traversal in `path.join`/`resolve` without root check.
367. `require()`/`import()` of user-controlled specifier.
368. `vm`/`node:vm` sandbox escapes (`this.constructor.constructor`).
369. `process.env` secrets logged/exposed.
370. `console.log` of request objects containing auth headers.
371. `debugger` statements (covered) — `alert()`/`confirm()` leftovers.
372. `==`/`!=` non-strict (covered) — `!= null` allowed idiom vs `== undefined`.
373. `var` instead of `let`/`const` (slop, low).
374. `== null` intentional — don't flag (already excluded).
375. Floating promises: `async` calls without `await`/`.catch`.
376. `Promise` without rejection handling (`unhandledrejection`).
377. `async` in loops serializing when parallel intended (perf hint).
378. `Array` holes/sparse arrays, `length` manipulation.
379. `arguments` object mutation.
380. `this` in callbacks losing context (`.bind` missing).
381. `==` vs `===` in switch cases.
382. `typeof` comparisons against wrong strings.
383. `parseInt` without radix.
384. `isNaN` vs `Number.isNaN` (global coerces).
385. `==` with `document.all` quirks.
386. `in` operator vs `hasOwnProperty` on objects.
387. `for...in` iterating prototype chain (needs hasOwnProperty).
388. `Object.keys` on null/undefined.
389. Spread of non-iterables.
390. Optional chaining overuse masking null bugs.
391. `JSON.stringify` circular refs throwing.
392. `BigInt`/`Number` mixing errors.
393. `Date` parsing inconsistencies (`new Date(userInput)`).
394. `Math.random` (covered) — `crypto.getRandomValues` preferred.
395. `btoa`/`atob` for "encryption" (encoding not crypto).
396. `Buffer.from(str)` default utf8 assumptions.
397. `Buffer` deprecated constructors.
398. `setTimeout`/`setInterval` with huge delays overflow.
399. `queueMicrotask`/`Promise` starvation patterns.
400. Event listener leaks: `addEventListener` without `removeEventListener` in SPA route changes.

## I. Other languages — Java/Kotlin/C/C++/C#/Rust/Swift/PHP/Ruby/Go-modules/etc. (401–450)

401. Java: `Runtime.exec`/`ProcessBuilder` with string commands.
402. Java: `ObjectInputStream.readObject` (covered) — `XMLDecoder`, `SnakeYAML` `new Yaml()`.
403. Java: `Statement.execute`/`createStatement` string SQL.
404. Java: `MessageDigest.getInstance("MD5"/"SHA-1")` passwords.
405. Java: `Cipher.getInstance("DES"/"ECB"/"RSA")` defaults.
406. Java: `TrustManager`/`HostnameVerifier` always-true.
407. Java: `FileInputStream`/`Paths.get` user paths.
408. Java: `Class.forName(user)` / reflection on user input.
409. Java: `ScriptEngine.eval`/` Nashorn`/`GraalJS` user scripts.
410. Java: `@PreAuthorize`/`@Secured` missing on controllers (framework heuristic).
411. Kotlin: `Runtime.exec`, `kotlin.io.path` user paths, `jacksonObjectMapper` polymorphic.
412. C/C++: `strcpy`/`strcat`/`sprintf`/`gets`/`scanf("%s")` unsafe functions.
413. C/C++: `system()`/`popen()` with user input.
414. C/C++: `malloc`/`free` mismatches, `alloca` in loops, integer overflow in `malloc(n*size)`.
415. C/C++: format-string bugs `printf(user)`.
416. C/C++: `memcpy`/`strncpy` off-by-one, missing NUL.
417. C/C++: `rand()`/`srand(time)` for security.
418. C/C++: `#include` of user-controlled paths, `dlopen` user libs.
419. C#: `Process.Start` with user args, `BinaryFormatter`/`LosFormatter`/`NetDataContractSerializer`.
420. C#: `XmlDocument`/`XmlReader` without `DtdProcessing.Prohibit`/`XmlResolver=null`.
421. C#: `Aes`/`DESCryptoServiceProvider`/`MD5`/`SHA1` for passwords.
422. C#: `Path.Combine` traversal, `File.ReadAllText(userPath)`.
423. C#: `BinaryFormatter`/`SoapFormatter`/`ObjectStateFormatter` deserialization.
424. C#: `AllowHtml`/`ValidateRequest=false` on ASP.NET.
425. C#: `ViewState`/`MAC` disabled (`EnableViewStateMac=false`).
426. C#: `Session`/`FormsAuth` cookie `requireSSL=false`, `httpOnlyCookies=false`.
427. C#: `connectionStrings`/`appSettings` hardcoded secrets.
428. Rust: `unsafe` blocks (count/flag for review), `unsafe impl Send/Sync`.
429. Rust: `unwrap()`/`expect()`/`panic!` in library paths.
430. Rust: `std::env::var` secrets in args/logs.
431. Rust: `Command::new` with user args, `shell` via `sh -c`.
432. Rust: `include_str!`/`include_bytes!` of generated secrets.
433. Rust: `mem::transmute`/`MaybeUninit` misuse.
434. Rust: `as` casts truncating (clippy-ish).
435. Swift: `UserDefaults` for secrets, `try!`/`as!` force unwraps.
436. Swift: `eval`/`NSSelectorFromString` dynamic dispatch.
437. PHP: `eval`/`assert`/`create_function`/`preg_replace /e` (covered partially).
438. PHP: `unserialize` (covered) — `extract()`/`parse_str` variable overwrite, `$$var` variable variables.
439. PHP: `include`/`require` user paths (LFI), `file_get_contents` user URLs (SSRF).
440. PHP: `mysql_*`/`mysqli_query` string concat SQL.
441. PHP: `password_hash`/`password_verify` preferred hints, `md5`/`sha1` passwords.
442. PHP: `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`$_SERVER` unsanitized sinks.
443. PHP: `header("Location: ".$user)` open redirect.
444. PHP: `extract($_REQUEST)` mass assignment.
445. Ruby: `eval`/`instance_eval`/`class_eval`/`send`/`public_send` user dispatch.
446. Ruby: `YAML.load`/`Marshal.load`/`Oj.load` unsafe modes.
447. Ruby: `system`/`exec`/backticks/`%x`/`IO.popen`/`Open3` with user input.
448. Ruby: `send_file`/`render file:`/`render inline:` user paths/templates.
449. Ruby: `ERB.new(user).result` SSTI.
450. Ruby: `redirect_to params[:url]` open redirect, `cookies` without flags.

## J. Slop & style — cross-language (451–500)

451. Commented-out code (covered) — extend run length to 3+ for stricter signal.
452. Lint suppressions (covered) — require justification text after suppression.
453. `TODO`/`FIXME`/`HACK`/`XXX` (covered) — categorize by author/area.
454. `console.log`/`print`/`println`/`dbg!`/`dd()`/`var_dump`/`dump`/`System.out` leftovers (partially covered).
455. `debugger`/`breakpoint`/`ipdb`/`binding.pry`/`require 'pry'` (covered partially).
456. Trailing whitespace (covered) — trailing whitespace in Markdown code blocks exempt.
457. Missing final newline (deferred) — detect via diff `\ No newline` marker.
458. Mixed tabs/spaces (covered) — per-file indent style consistency report.
459. Lines >120 chars (covered) — make threshold configurable per language.
460. Excessive blank lines (covered) — >2 consecutive.
461. Long functions (Go/Python covered) — JS/Java/C#/Rust equivalents.
462. High parameter counts (Go covered) — other languages.
463. Cyclomatic complexity (Go covered) — other languages via token proxies.
464. Deep nesting (covered) — raise/lower threshold per language config.
465. `else` after `return` (covered Go/brace/Python) — Ruby/Lua/Perl variants.
466. Boolean literal returns (covered Go) — other languages.
467. Unreachable code (covered) — switch-case fallthrough detection.
468. Ignored error returns (covered Go/Python pass) — JS unchecked promises, Rust `let _ =`.
469. `_ =` discards in Go (covered) — named-blank patterns `_x`.
470. `interface{}`/`any` overuse as "any type" smell.
471. `float` for money/IDs (precision slop).
472. `==` float equality comparisons.
473. `String` concat in loops (covered Go) — JS `+=` in loops, Python `+` in loops, Java `StringBuilder` hints.
474. `new Array(n)` holes, `Array(n).fill` patterns.
475. Regex compiled in loop/function (covered Go MustCompile) — JS `new RegExp` in loops, Python `re.compile` in functions.
476. `import` inside function bodies (Python/JS lazy imports as smell).
477. Circular dependencies between modules (import graph heuristic).
478. Dead exports: exported symbols never imported elsewhere (needs whole-repo graph — future).
479. Unused variables/imports (needs typecheck — defer to `go vet`/`eslint` integration hints).
480. Duplicate function names across files (namespace collision heuristic).
481. Copy-pasted blocks within file (covered) — near-duplicates (fuzzy hash).
482. Copy-pasted blocks across files (covered) — near-duplicates.
483. Magic numbers/strings without named constants (heuristic, config-gated).
484. `if x == true`/`if x == false` (covered Go) — other languages.
485. `return true`/`return false` if-else chains (covered Go) — others.
486. `while True` + `break` vs `for` idiom.
487. `try/except/pass` (covered) — `try/finally` without except.
488. `catch` that only logs (covered JS) — other languages.
489. Empty `catch`/`except`/`rescue` blocks (covered) — `on error resume next` VB.
490. `goto`/labels (Go covered-ish) — other languages.
491. `var` hoisting surprises (JS).
492. `arguments`/`this` misuse (JS).
493. `eval`-adjacent "config as code" smells.
494. `print` debugging leftovers in scripts (partially covered).
495. Commented license headers duplicated per file (verify dedup).
496. Inconsistent naming conventions within file (camelCase vs snake_case mixing).
497. Abbreviated names (`tmp`, `x`, `data`, `obj`) in long functions.
498. Boolean parameter flags (`doThing(true, false)`) — suggest options struct/enum.
499. Functions with >3 levels of boolean operators.
500. `switch`/`if-else` chains that should be lookup tables/maps.

## K. Performance (501–550)

501. N+1 query patterns (ORM loops with queries inside).
502. Queries in loops without batching/preload hints.
503. `SELECT *` in ORMs/SQL.
504. Missing indexes hinted by `WHERE` on unindexed-looking columns (heuristic only).
505. Unbounded `SELECT`/`find` without `LIMIT`.
506. `OFFSET` pagination on large tables (keyset suggestion).
507. Cache without TTL/eviction.
508. Cache stampede: no singleflight/mutex on hot keys.
509. In-memory caches unbounded (map growth).
510. `strings.Join`/`+` concat in loops (covered Go) — other languages.
511. Repeated regex compilation (covered) — `re.compile`/`new RegExp`/`preg_match` in loops.
512. `fmt.Sprintf`/`printf`-style in hot paths (allocation hints).
513. `reflect`/`interface{}` dispatch in hot loops.
514. `json.Marshal`/`Unmarshal` of large structs per request.
515. Missing pagination on list endpoints.
516. Synchronous I/O in request handlers (file/network in handler).
517. `time.Sleep` retry loops without backoff/jitter.
518. Retry without max attempts/timeout.
519. Connection pools undersized/unbounded (`MaxOpenConns` unset).
520. HTTP clients created per-request (no reuse).
521. `defer` in hot loops accumulating.
522. Goroutine-per-request without semaphore (unbounded concurrency).
523. Worker pools without bounds.
524. Channel buffer sizes = 0 causing convoy.
525. `sync.Mutex` held across I/O.
526. `RWMutex` used where `Mutex` suffices (or vice versa).
527. False sharing on hot atomics (padding hints).
528. Large struct copies by value in hot paths.
529. Slice growth without capacity hints (`make([]T, 0, n)`).
530. `map` with predictable iteration needs sorted output.
531. `sort` inside loops recomputing.
532. `strings.Contains`/`Index` in O(n²) patterns.
533. Regex without anchors causing full scans.
534. `filepath.Walk`/`os.ReadDir` recursive without depth limit.
535. Loading entire files into memory (`ioutil.ReadFile` on large files).
536. `io.Copy` without buffer size tuning.
537. Image processing without size limits (decompression bombs).
538. `encoding/gob`/`json` on untrusted large payloads.
539. DB transactions held open across network calls.
540. Long-running transactions / idle-in-transaction.
541. Missing `context` propagation (cancellation ignored).
542. `context.Background()` in request handlers (detached cancellation).
543. Timeouts missing on outbound calls (covered partially).
544. DNS resolution without timeout.
545. Connection leaks: unclosed DB/HTTP/file handles (partially covered).
546. `defer rows.Close()` after early `return` skipping close? (covered by close checks).
547. Batch inserts row-by-row instead of bulk.
548. `INSERT ... ON CONFLICT`/upsert patterns missing.
549. Read replicas not used for read-heavy paths (architecture note).
550. CDN/static asset caching headers missing (`Cache-Control`, `ETag`).

## L. Workflow, CLI & UX (551–600)

551. `--format json` output option for machine consumption.
552. `--format sarif`/`github` (done) — add `codeclimate`, `checkstyle`, `junit`.
553. `--output <file>` to write report to path.
554. `--quiet`/`--verbose` levels.
555. `--color`/`--no-color` for TTY detection.
556. Exit codes documented & distinct (0 clean, 1 findings, 2 error).
557. `--fail-on` per-severity (done) — `--fail-on-rule <name>`.
558. `--baseline <file>` to ignore known findings (fingerprint-based).
559. `--since <ref>`/`--until <ref>` range reviews.
560. `--staged`/`--unstaged`/`--all` diff scope flags.
561. `--include`/`--exclude` path globs for files.
562. `--max-findings` cap with truncation notice.
563. `--sort-by severity|file|rule` output ordering.
564. `--group-by rule|file|severity` report grouping.
565. `--summary-only` mode for CI logs.
566. `--json` findings stream (NDJSON) for tooling.
567. `--watch` mode re-running on file changes.
568. `--fix`/`--suggest` auto-fix hints where safe (e.g., `== true` → drop).
569. `m3tal-review diff` command reviewing arbitrary diff files.
570. `m3tal-review stdin` reading diff from stdin.
571. `m3tal-review ci` preset profile for CI environments.
572. `m3tal-review init` scaffolding config/policy/hook.
573. `m3tal-review config` show effective configuration.
574. `m3tal-review rules` alias for `list-rules` with `--format json`.
575. `m3tal-review explain --examples` with sample diffs per rule.
576. `--explain` showing severity rationale + false-positive notes.
577. Interactive `m3tal-review tui` browser for findings.
578. `m3tal-review annotate` printing findings as code comments.
579. `m3tal-review patch` generating a patch of suggested fixes.
580. `--editor` integration jumping to finding locations.
581. Shell completions (bash/zsh/fish).
582. Man page / `--help` per-command detail.
583. `M3TAL_REVIEW_*` env var configuration.
584. Config file discovery: `.m3tal-review.json`/`toml`/`yaml`.
585. Per-directory config overrides.
586. `--profile` presets beyond fast/full (e.g., `security`, `slop`, `ci`).
587. `--rule <name>` run single rule.
588. `--rules-file` custom rule pack (regex rules in config).
589. Severity override via CLI (`--severity code-slop=low`).
590. `--ignore-file` custom ignore path.
591. `--policy` custom policy file path.
592. `--no-history`/`--no-report` for ephemeral runs.
593. `--report-dir` custom storage location.
594. `--temp-dir` for large diff processing.
595. `--jobs N` parallelism control.
596. `--timeout` per-rule/per-file timeouts.
597. `--max-diff-size` guard against huge diffs.
598. `--max-file-size` skip giant files with notice.
599. Progress indicator for long audits.
600. Estimated-time display for `audit` on large repos.

## M. Reports, history & tracking (601–650)

601. Report delta view: new/resolved findings vs last run (partially via FindingChanges — surface in CLI summary).
602. `m3tal-review history --diff` comparing two runs.
603. `m3tal-review history --rule <name>` filtering history.
604. `m3tal-review history --since <date>` time filtering.
605. Finding trend charts (counts over time) — ASCII sparkline in CLI.
606. Per-rule hit counts over history (identify noisy rules).
607. False-positive feedback loop: `m3tal-review suppress --reason` writing to ignore file.
608. `m3tal-review triage` interactive accept/dismiss flow.
609. Finding comments/notes attached to fingerprints.
610. Finding assignment/ownership metadata.
611. SLA/aging tracking on unresolved findings.
612. Report signing/checksums for integrity.
613. Report encryption for sensitive repos.
614. Report retention/rotation policy.
615. History compaction (JSONL → monthly archives).
616. History search (`m3tal-review history --grep`).
617. Export history to CSV/JSON for external dashboards.
618. Webhook notifications on new critical findings.
619. Slack/Discord/Email notification on `--fail-on` triggers.
620. GitHub Check Run / commit status integration (`--github-check`).
621. GitLab CI report integration (`--gitlab-sast`?).
622. JUnit XML output for CI test aggregation.
623. SARIF upload helper (`--upload-sarif` to GitHub code scanning).
624. Baseline file generation (`--write-baseline`).
625. Baseline diff review (only new findings vs baseline).
626. Fingerprint stability improvements: normalize whitespace/renames.
627. Finding deduplication across rules (same root cause, multiple rules).
628. Severity calibration report (rule severity vs actual fix rate).
629. Per-language/per-rule coverage matrix in reports.
630. Unanalyzed-files report detail (why each was skipped).
631. Machine-readable "skipped" reasons in JSON output.
632. Report includes rule versions for reproducibility.
633. Diff hash + source hash per file in report for audit trail.
634. Signed commits/attestation of review runs.
635. SBOM-ish manifest of analyzed files.
636. Report diffing between branches.
637. "Why was this suppressed?" audit trail (`--explain-suppression`).
638. Suppression expiry dates (`ignore until 2025-01-01`).
639. Per-finding confidence score (heuristic strength).
640. Finding confidence tiers: definite/likely/possible.
641. "Needs human review" bucket separate from findings.
642. Auto-triage suggestions (likely FP vs likely real).
643. Report includes policy file hash used.
644. History entry includes tool version + rule set hash.
645. Rollback/audit of suppression changes over time.
646. Multi-repo aggregate reports (monorepo rollup).
647. Per-package/module breakdown in reports.
648. Hotspot analysis: files with most findings over time.
649. Regression detection: findings reintroduced after being resolved.
650. "Clean streak" tracking per file/rule.

## N. Policy, config & customization (651–700)

651. Policy: per-rule enable/disable (done) — per-severity override (done) — per-path overrides.
652. Policy: `only`/`skip` lists in config file.
653. Policy: custom severity per path glob (`{"*.test.go": {"code-slop": "info"}}`).
654. Policy: per-language rule toggles.
655. Policy: thresholds config (nesting depth, function length, line length).
656. Policy: `ignore` patterns inline in policy (vs separate ignore file — unify).
657. Policy: `extends`/`$ref` for shared policy files.
658. Policy: JSON Schema validation with helpful errors.
659. Policy: hot-reload in watch mode.
660. Policy: `require_together` already exists — extend to file pairs, migrations.
661. Policy: forbidden/required file patterns (license headers, NOTICE files).
662. Policy: required checks per path (e.g., tests must accompany src changes).
663. Policy: branch protection hints (findings block merge).
664. Policy: exception workflow with expiry + justification.
665. Policy: team/owner-based routing of findings.
666. Policy: severity inflation for `risk_paths` (exists?) — verify.
667. Policy: `min_confidence` filter to hide low-confidence findings.
668. Policy: `max_findings_per_rule` caps.
669. Policy: language-specific rule packs toggled by repo contents.
670. Policy: environment-specific profiles (`dev`/`ci`/`release`).
671. Config: `m3tal-review.toml` support.
672. Config: env-var expansion in config values.
673. Config: `${VAR}`/`~` path expansion safety.
674. Config: config file itself reviewed for safety (no symlinks — done partially).
675. Config: atomic config writes (temp+rename).
676. Config: backup of previous config on change.
677. Config: `m3tal-review config validate` command.
678. Config: `m3tal-review config diff` showing effective vs file.
679. Config: per-rule custom messages/remediation overrides.
680. Config: custom regex rules defined in config (safe regex engine, size limits).
681. Config: custom file-type → rule mappings.
682. Config: exclude generated files (`// Code generated`, `*.pb.go`, `*.min.js`).
683. Config: include/exclude vendor dirs (`vendor/`, `node_modules/`, `.git/`).
684. Config: max file size / max diff size limits.
685. Config: encoding handling (UTF-8 validation, BOM stripping).
686. Config: line-ending normalization (CRLF/LF).
687. Config: case-sensitivity of path globs.
688. Config: symlink handling policy (follow/skip/error).
689. Config: submodule handling (skip/recurse).
690. Config: git worktree support.
691. Config: bare repo / no-index mode.
692. Config: shallow clone handling.
693. Config: merge-commit / conflict-marker detection in diffs.
694. Config: binary file detection improvements (NUL-byte heuristic tuning).
695. Config: encoding detection for non-UTF8 files (latin-1 fallback).
696. Config: huge-file streaming instead of full read.
697. Config: `.gitattributes` linguist overrides respected.
698. Config: generated-file detection via `.gitignore` patterns.
699. Config: monorepo package boundaries for scoping.
700. Config: remote policy fetching (signed) for org-wide rules.

## O. Testing infrastructure (701–750)

701. Golden-file tests for report JSON stability.
702. Snapshot tests for SARIG/GitHub output formats.
703. Table-driven rule tests (already per-rule) — unify into shared harness.
704. Fuzz `ParseDiff` (deferred) — add `FuzzParseDiff`.
705. Fuzz `matchesRepoPath` glob matcher.
706. Fuzz `maskNonCode`/`sourceCodeMask` for panics.
707. Fuzz policy file parsing (`readReviewPolicy`).
708. Fuzz `inlineSuppressions` marker parsing.
709. Fuzz `findingFingerprint` stability.
710. Fuzz rule `Check` functions with random diffs (crash-only).
711. Benchmarks: `ParseDiff` on large diffs.
712. Benchmarks: `analyzeGoSourceAST` on large files.
713. Benchmarks: `sourceBlocks`/`readRuleSource` cache hit rate.
714. Benchmarks: `Engine.Run` parallel vs sequential.
715. Benchmarks: `maskNonCode` on minified JS.
716. Coverage report in CI (`go test -coverprofile`).
717. Coverage gate threshold (e.g., 70%).
718. Mutation testing spot-checks on critical rules.
719. Integration test: full `review` on fixture repo end-to-end.
720. Integration test: `audit` on fixture working tree.
721. Integration test: `install-hook` + pre-commit run.
722. Integration test: `--base` mode on fixture branch.
723. Integration test: SARIF output validated against schema.
724. Integration test: suppression end-to-end (comment → no finding).
725. Integration test: ignore-file end-to-end.
726. Integration test: policy overrides end-to-end.
727. Integration test: `--fail-on` exit codes.
728. Integration test: parallel engine race-detector clean (`-race`).
729. Race-detector CI job.
730. `go vet` + `staticcheck` + `golangci-lint` in CI.
731. Dependency vulnerability scanning (`govulncheck`) in CI.
732. License scanning of dependencies.
733. SBOM generation for the tool itself.
734. Reproducible builds (`-trimpath`, `-buildvcs`).
735. Cross-platform builds (linux/darwin/windows) in CI.
736. ARM64 builds.
737. Release automation: tag → build → sign → publish.
738. Changelog generation from commits.
739. Semantic versioning enforcement.
740. Deprecation policy for flags/rules.
741. `m3tal-review version --json` machine-readable.
742. Health check command (`m3tal-review doctor` — git present, writable dirs).
743. Self-test command (`m3tal-review selftest` running fixture suite).
744. Debug/trace logging behind `--debug`/`M3TAL_DEBUG`.
745. Profiling hooks (`--cpuprofile`, `--memprofile`).
746. Crash reporting with stack traces (opt-in).
747. Telemetry opt-in for rule usage stats.
748. Anonymous usage metrics (opt-in, privacy-preserving).
749. Error message quality audit (actionable, no leaks).
750. i18n of user-facing strings (deprioritize).

## P. CI/CD integration (751–800)

751. GitHub Action for m3tal-review (`action.yml` wrapping binary).
752. Pre-commit framework hook (`.pre-commit-hooks.yaml`).
753. GitLab CI template/include snippet.
754. CircleCI orb.
755. Jenkins shared library step.
756. Azure DevOps task extension.
757. Bitbucket Pipes integration.
758. Drone CI plugin.
759. Buildkite plugin/step.
760. `reviewdog`-compatible output for inline PR comments.
761. GitHub Code Scanning SARIF upload docs+helper.
762. GitLab SAST report format output.
763. Checkstyle/PMD-compatible XML output.
764. JUnit XML for test-report aggregation.
765. CodeClimate JSON output.
766. SonarQube-compatible issue import format.
767. DefectDojo/Defect tracker webhook payloads.
768. Linear/Jira issue creation from findings (opt-in).
769. PR comment summarization bot mode.
770. Auto-suggest fixes as PR suggestions (` ```suggestion ` blocks).
771. Commit-status API integration (`--status pending|success|failure`).
772. Required-check naming conventions doc.
773. Merge-queue friendly incremental reviews.
774. Nightly full-repo audit vs per-PR staged review split.
775. Scheduled audit with diff-vs-yesterday reporting.
776. Release-gate profile (stricter severities).
777. Hotfix profile (minimal rules, fast).
778. Monorepo path-filtered rule sets.
779. Per-team policy inheritance.
780. Org-wide baseline sharing (signed).
781. CI caching of `.m3tal-review` artifacts between runs.
782. Incremental audit via content-hash cache (deferred item).
783. Distributed review sharding for huge repos.
784. Self-hosted runner compatibility notes.
785. Air-gapped/offline mode (no network assumptions).
786. Proxy support for tool downloads.
787. Corporate registry/mirror support.
788. Windows CI quirks documentation.
789. Alpine/musl static binary builds.
790. `go install` one-liner docs verification.
791. Homebrew tap formula.
792. Debian/RPM package builds.
793. Docker image for the tool.
794. distroless/scratch image option.
795. Sigstore/cosign signing of releases.
796. SLSA provenance attestation.
797. SBOM for releases.
798. Vulnerability disclosure policy (SECURITY.md).
799. CVE monitoring for the tool's own deps.
800. Dependency update automation (Renovate/Dependabot config for this repo).

## Q. Supply-chain depth (801–850)

801. Lockfile integrity checks (`go.sum`/`package-lock`/`Cargo.lock` tamper hints).
802. Dependency confusion: internal package names vs public registry.
803. Typosquatting detection on new deps (edit-distance to popular names).
804. New dependency review: first-seen packages flagged for manual review.
805. `replace`/`vendor`/`path` overrides in go.mod flagged.
806. `postinstall`/`preinstall`/`install` scripts in package.json flagged.
807. `git+`/`http:`/`file:` dependency specifiers flagged.
808. Floating version ranges (`latest`, `*`, `>=`) in manifests.
809. `npm` lifecycle scripts with network/exec.
810. `pip`/`setup.py` `setup_requires`/`install_requires` oddities.
811. `cargo` build scripts (`build.rs`) flagged for review.
812. Git submodule URL pinning (commit SHA vs branch).
813. Submodule `.gitmodules` URL changes flagged.
814. `.gitignore`d secret patterns double-check (e.g., `.env` committed despite ignore).
815. Git history secret scanning hook (optional `--history` mode).
816. Force-push/branch-rewrite detection in reviewed diffs.
817. Merge commits with conflict markers committed (`<<<<<<<`).
818. Binary blobs committed (detect by extension+NUL heuristic).
819. Large-file commits (>1MB) flagged.
820. Generated files committed that should be gitignored.
821. `node_modules`/`vendor`/`dist` committed contents flagged.
822. `.github/CODEOWNERS` missing for sensitive paths.
823. Branch protection rules can't be verified locally — doc note.
824. Signed-tag/commit verification hints (`git verify-commit`).
825. SLSA/in-toto attestation presence checks for artifacts.
826. Container base image CVE hints (needs external DB — defer).
827. License compatibility scan of deps (SPDX hints).
828. Copyleft license contamination warnings.
829. AGPL/GPL in distributed binaries warning.
830. Trademarked name usage in package metadata (low).
831. `package.json` `repository`/`homepage` typosquats.
832. `go.mod` module path mismatches with repo URL.
833. `README` badges from untrusted domains (tracking pixels).
834. Docs links to `http://` (mixed content in docs).
835. `curl|sh` in README install instructions (docs rule).
836. Install scripts downloading unpinned artifacts.
837. Homebrew formula `url`/`sha256` consistency.
838. Snap/Flatpak manifest permission review.
839. VS Code extension `activationEvents`/`workspace` trust issues.
840. Browser extension `permissions`/`host_permissions` review.
841. Mobile app: hardcoded API endpoints/keys in manifests.
842. Mobile: cleartext traffic permitted (`usesCleartextTraffic`).
843. iOS: ATS exceptions (`NSAllowsArbitraryLoads`).
844. Android: exported components without permission checks.
845. Deep-link handling without validation.
846. WebView `addJavascriptInterface`/`setJavaScriptEnabled` risks.
847. Electron: `nodeIntegration`, `contextIsolation` disabled, `webSecurity` off.
848. Electron: `shell.openExternal` with user URLs.
849. Tauri: `dangerousDisableAssetCspModification`, fs/shell plugin scopes.
850. Expo/RN: `source maps` in prod, `console.log` in release builds.

## R. Documentation & onboarding (851–900)

851. Per-rule docs pages (generated from rule metadata).
852. Rule severity rationale documented.
853. False-positive guide per rule (common FPs + how to suppress).
854. Migration guide for renamed rules/flags.
855. FAQ: "why did X not get flagged?"
856. Architecture doc: pipeline stages (diff → mask → rules → filter → report).
857. Contributing guide for new rules (checklist template).
858. Rule-authoring SDK/helpers doc (`patternRule`, `langPattern`, `sourceBlocks`).
859. Testing guide for rule authors (fixture diff format).
860. Performance tuning guide for large repos.
861. Security model doc (what's trusted/untrusted).
862. Threat model for the reviewer itself.
863. Comparison matrix vs golangci-lint/eslint/brakeman (honest positioning).
864. "Heuristic, not proof" disclaimers per category.
865. Example CI configs (GitHub Actions, GitLab, pre-commit).
866. Example policy files (strict/permissive/team).
867. Example ignore files.
868. Video/GIF demo of CLI output.
869. Changelog highlights per release.
870. Deprecation notices in `--help`.
871. `--help` examples per flag.
872. Glossary (finding, fingerprint, baseline, profile).
873. Troubleshooting: "no staged changes", "git not found", "permission denied".
874. Troubleshooting: large repo performance tips.
875. Troubleshooting: why a rule didn't fire (debug mode doc).
876. Docs for `--debug`/trace output format.
877. Docs for report JSON schema (versioned).
878. Docs for history JSONL schema.
879. Docs for policy JSON schema.
880. Docs for ignore-file syntax.
881. Docs for suppression comment syntax (all comment styles).
882. Docs for custom regex rules in config.
883. Docs for exit codes.
884. Docs for SARIF/GitHub output semantics.
885. Docs for fingerprint stability guarantees.
886. Docs for `--base` mode semantics.
887. Docs for audit vs review differences.
888. Docs for unanalyzed-files categories.
889. Docs for tool scanner integration (`--with-tools`).
890. Docs for confidence checks (`--profile full`).
891. Docs for path safety guarantees.
892. Docs for symlink/policy-file protections.
893. Docs for resource limits (output caps, file size).
894. Docs for determinism guarantees.
895. Docs for supported languages matrix (detection depth per language).
896. Docs for known limitations per rule.
897. Docs for false-positive tuning via policy.
898. Docs for contributing detectors in new languages.
899. Docs for release process.
900. Docs site (mkdocs/docusaurus) vs README split.

## S. Internals & architecture (901–950)

901. Rule registry/reflection to auto-register rules (avoid manual defaultRules list drift).
902. Rule metadata struct (name, description, severity, languages, version) centralized.
903. Pluggable rule interface versioning.
904. Rule result streaming (don't buffer all findings).
905. Incremental per-file rule evaluation with early-exit budgets.
906. Shared parsed-AST cache across Go rules (currently each rule reparses? verify — slop parses once; other Go rules are regex — unify Go AST access).
907. Shared tokenizer for brace languages across rules.
908. Language detection caching per file.
909. `maskNonCode` result caching per file (currently recomputed per rule).
910. `sourceBlocks` result caching across rules in one run.
911. Diff parsing once, share `[]FileDiff` across all rules (currently each rule reparses the diff string! — big win).
912. `ParseDiff` output reuse: pass parsed structure to rules instead of raw string (API change).
913. Parallelism within `sourceBlocks` file reads.
914. Bounded worker pool for rule execution (limit = GOMAXPROCS).
915. Memory-mapped or streamed diff processing for huge diffs.
916. Spool large file contents to temp files instead of memory.
917. Object pool for regex match results.
918. Interned strings for repeated file paths/rule names.
919. Finding struct size optimization (string interning, int line packing).
920. Report JSON streaming marshal (avoid building full doc in memory).
921. History JSONL append with fsync policy.
922. Report write atomicity (temp+rename — verify exists).
923. Locking for concurrent CLI invocations on same repo (currently? verify — likely none → add lockfile).
924. Stale `.m3tal-review` cleanup (old reports retention).
925. Config validation at startup (fail fast on bad policy).
926. Graceful degradation when git missing (some commands work without?).
927. Git worktree/submodule edge cases in diff collection.
928. `GIT_DIR`/`GIT_WORK_TREE` env respect.
929. Bare repository handling.
930. Detached HEAD handling in reports.
931. Unborn branch (no commits) handling — exists, verify edge cases.
932. Merge conflict state detection (`MERGE_HEAD` exists → warn).
933. Rebase/cherry-pick in progress detection.
934. Stash interactions (review staged only — document).
935. `git diff --cached` vs `git stash show` equivalence notes.
936. Intent-to-add (`git add -N`) handling.
937. Renames detection (`-M`) in diffs for moved-code findings.
938. Copy detection (`-C`) for duplicated-block across rename.
939. Binary diff handling (`--binary` patches).
940. Submodule diff (`gitlink`) handling — flagged unanalyzed already.
941. Symlinked files in diffs (mode 120000) handling.
942. File mode changes (100644→100755) flagged — exists, extend to setuid bits.
943. `.gitattributes` `diff=` drivers affecting parsed diffs.
944. `core.autocrlf` line-ending normalization consistency.
945. `core.fsmonitor` disabled (done) — other repo-config command executions audit (`core.sshCommand`, `core.pager`, hooks).
946. `core.hooksPath` custom hooks not run during review (verify).
947. Git alias expansion safety (`git config alias.*` can't inject into our fixed args — verify arg order).
948. `GIT_SSH_COMMAND`/`GIT_ASKPASS` env passthrough to git subprocess (we don't fetch — verify no network ops).
949. `git` version compatibility matrix (minimum version check).
950. Graceful error when repo has no commits/no HEAD.

## T. Edge cases & robustness (951–1000)

951. Empty diff handling (exists) — diff with only mode changes.
952. Diff with only deletions (no added lines) — rules should no-op cleanly.
953. Diff with only renames (no content change).
954. Diff with conflict markers committed.
955. Malformed diff input (truncated hunk, bad counts) — parser robustness + fuzz.
956. Extremely long lines (>1MB single line) — scanner limits.
957. Files with no trailing newline — `\ No newline` marker handling in AddedText.
958. CRLF line endings in diffs — normalization consistency.
959. UTF-8 BOM in files — offset/line-number drift.
960. UTF-16/other encodings — detect & skip or convert.
961. Invalid UTF-8 bytes — replacement char handling in regexes.
962. NUL bytes in "text" files — binary detection threshold.
963. Files >100MB — streaming/skip policy.
964. Diffs >10k files — batching/progress.
965. Paths with unicode/normalization forms (NFC vs NFD).
966. Paths with spaces/special chars in git output parsing (`-z` mode?).
967. Paths with quotes/backslashes/newlines (git quotes them — unquote correctly).
968. Case-insensitive filesystems (macOS) path matching.
969. Case-sensitive vs insensitive glob matching config.
970. Windows path separators in diffs (`\` vs `/`).
971. Absolute paths in diffs (shouldn't happen — defense).
972. `..` segments post-`filepath.Clean`.
973. Symlinked repo root / worktree.
974. `.git` file (worktree/submodule) vs directory.
975. `GIT_DIR` env overriding repo detection.
976. Read-only repository (`.git` perms) — report write failures graceful.
977. Disk-full during report write — error message quality.
978. Concurrent runs on same repo — lockfile (see #923).
979. Clock skew affecting history timestamps.
980. Timezone handling in history/report timestamps (UTC normalize?).
981. Locale-dependent string ops (case folding, trimming).
982. Regex catastrophic backtracking on adversarial diffs (RE2 is safe — verify no `regexp` backtracking; PCRE not used — good).
983. Memory exhaustion via many findings (cap + warn).
984. Finding message length caps (untrusted content in messages).
985. Rule panics — per-rule recover() to isolate failures (currently? verify — add if missing).
986. Rule timeouts — hung rule detection (context deadline per rule).
987. Signal handling (SIGINT graceful shutdown mid-audit).
988. Exit code on partial failure (some rules errored).
989. stderr vs stdout separation for machine parsing.
990. TTY detection for color/progress.
991. Pipe/redirect behavior (`| head` SIGPIPE handling).
992. `NO_COLOR`/`CLICOLOR` env respect.
993. Terminal width adaptation for tables.
994. Non-UTF8 terminal locales.
995. `TERM=dumb` fallback.
996. JSON output escaping of control chars (done via encoding/json — verify finding messages sanitized).
997. SARIF URI escaping for weird filenames.
998. GitHub annotation escaping (`%`, `\r`, `\n`, `,`, `:` — done; verify `]`/`]` in file paths).
999. Report path traversal via runID (validated 16-hex — verify all writers).
1000. History JSONL injection via crafted finding fields (newline in message → JSON escaped — verify).
