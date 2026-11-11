package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
)

type ruleDoc struct {
	Name        string
	Description string
	Example     string
}

var ruleCatalog = []ruleDoc{
	{"code-slop", "Code-quality heuristics: redundant boolean comparisons, empty blocks, deep nesting, else-after-return, unreachable code, long functions, mutable defaults, duplicated blocks, lint suppressions, and more (see README for the full per-language list).", "if x == true { ... }"},
	{"todo-marker", "TODO/FIXME/XXX markers in comments and Markdown task headings.", "// TODO: handle this"},
	{"debug-leftover", "Likely debug output: fmt.Print*, console.log, println, debugger, breakpoint, etc.", "fmt.Println(\"debug\")"},
	{"hardcoded-credential", "Credential-looking name/value assignments in source.", "password = \"hunter2\""},
	{"exposed-secret", "High-confidence secret formats: PEM private keys and provider tokens (AWS, GitHub, GitLab, Slack, OpenAI, Stripe, Google, npm).", "AKIA..."},
	{"high-entropy-secret", "Entropy-based secret detection: high-entropy strings guarded by character sets (Hex, Base64, Base58), length gates, and secret contexts.", "apiKey = \"4f7a9c8b2e1d0f5a3b6c8e9d1a2f4b7c89abcdef\""},
	{"path-traversal", "File APIs fed by request input or os.Args without sanitization.", "os.Open(r.URL.Path)"},
	{"request-taint", "Intra-file taint: request-derived values (URL params, query, form, decoded bodies) reaching filesystem, serving, or exec sinks.", "name := chi.URLParam(r, \"name\"); os.RemoveAll(dir)"},
	{"wildcard-default-scope", "Permission/scope normalization that falls back to wildcard or full access on empty/invalid input.", "if len(out) == 0 { return []string{\"*\"} }"},
	{"plugin-trust", "Auto-execution of discovered plugins, CWD-relative plugin paths, and credential env vars passed to plugin subprocesses.", "exec.Command(spec.Command)"},
	{"privileged-pkg-exec", "Package managers or privilege wrappers (sudo, dpkg, apt, systemctl) executed from HTTP handler code.", "exec.Command(\"sudo\", \"dpkg\", \"-i\", debPath)"},
	{"process-kill-abuse", "Process termination whose target PID may be request-controlled.", "proc.Kill() // pid from chi.URLParam"},
	{"credential-in-query", "Credentials read from URL query parameters (leak via logs, history, referrers).", "r.URL.Query().Get(\"token\")"},
	{"cleartext-transport", "Plain-HTTP server serving credential-bearing endpoints with no TLS configuration.", "http.ListenAndServe(\":8080\", handler)"},
	{"unauthenticated-route", "Parameterized route registered outside the authenticated API namespace in a file that uses auth middleware.", "r.Get(\"/plugins/{name}/*\", handler)"},
	{"weak-cryptography", "MD5/SHA-1/DES/RC4 for security purposes; math/rand/random/Math.random for token-like values.", "md5.Sum(data)"},
	{"unsafe-deserialization", "pickle/marshal/yaml.load/unserialize/node-serialize of untrusted data.", "pickle.loads(blob)"},
	{"dangerous-eval", "eval/exec/new Function/string setTimeout/assert-style dynamic execution.", "eval(userInput)"},
	{"cross-site-scripting", "innerHTML/outerHTML/document.write/dangerouslySetInnerHTML and template bindings that render raw HTML.", "el.innerHTML = data"},
	{"sql-injection", "String-built SQL queries via fmt.Sprintf/concat/f-strings/template literals.", "fmt.Sprintf(\"SELECT * FROM u WHERE id=%s\", id)"},
	{"insecure-tls-verification", "TLS certificate verification disabled (InsecureSkipVerify, VERIFY_NONE, NODE_TLS_REJECT_UNAUTHORIZED=0).", "InsecureSkipVerify: true"},
	{"risky-shell-execution", "Shell command execution with interpolated input.", "exec.Command(\"sh\", \"-c\", cmd)"},
	{"world-writable-file-mode", "Files created with world-writable permissions (0777/0666).", "os.Chmod(f, 0777)"},
	{"review-risk", "Changed paths matching configured high-risk globs in .m3tal-review-policy.json.", "risk_paths: [\"internal/auth/**\"]"},
	{"review-policy", "Policy violations: forbidden paths and missing coupled changes.", "forbidden_paths: [\"secrets/**\"]"},
	{"review-policy-config-error", "The .m3tal-review-policy.json file could not be loaded.", "invalid JSON"},
	{"code-slop-analysis-error", "A staged file could not be parsed for syntax-aware analysis.", "unbalanced braces"},
	{"repository-lint", "Repository lint command (gofmt/go vet/custom) reported issues.", "gofmt -l ."},
	{"confidence-*", "Confidence checks (gofmt, go vet, go test, optional scanners) failed.", "go test ./..."},
	{"ssrf", "Server-side request forgery: HTTP clients fetching request-controlled URLs.", "http.Get(r.URL.Query().Get(\"u\"))"},
	{"command-injection", "Shell/process execution built from request or interpolated data.", "exec.Command(\"sh\", \"-c\", input)"},
	{"open-redirect", "Redirect targets derived from request parameters.", "redirect(request.args.get('next'))"},
	{"template-injection", "Templates rendered from user-controlled names or content.", "render_template_string(request.args['t'])"},
	{"prototype-pollution", "Object merges/assignments with user-controlled keys; __proto__ access.", "Object.assign(out, req.body)"},
	{"archive-extraction", "Archive extraction without member path validation (zip-slip).", "zipfile.extractall('/tmp')"},
	{"xxe", "XML parsing APIs without entity-expansion protection.", "DocumentBuilderFactory.newInstance()"},
	{"injection-other", "LDAP/XPath/header/mass-assignment injection variants.", "header('Location: ' . $_GET['next'])"},
	{"unsafe-code", "unsafe/cgo/syscall/native-interface usage needing review.", "unsafe.Pointer arithmetic"},
	{"secret-file", "Committed files that look like secret material by name.", ".env.production"},
	{"jwt-misuse", "JWT 'none' algorithm or disabled signature verification.", "jwt.decode(t, options={'verify_signature': False})"},
	{"hardcoded-session-secret", "Session/JWT secrets hardcoded in source.", "const SESSION_SECRET = \"...\""},
	{"tls-verification", "TLS verification disabled or deprecated protocol versions.", "InsecureSkipVerify: true"},
	{"weak-crypto-params", "ECB mode, static IVs, weak hashes, deprecated ciphers.", "hashlib.md5(data)"},
	{"timing-unsafe-compare", "Secret comparisons using ==/=== instead of constant-time functions.", "password == expected"},
	{"insecure-randomness", "Non-CSPRNG randomness for security-sensitive values.", "Math.random() for tokens"},
	{"insecure-permissions", "World-readable/writable permissions on sensitive files.", "chmod 777 secret.key"},
	{"cors-misconfig", "Wildcard CORS origin combined with credentials.", "Access-Control-Allow-Origin: *"},
	{"cookie-flags", "Session cookies missing Secure/HttpOnly/SameSite; remember-me policy.", "document.cookie = session"},
	{"web-storage-secrets", "Tokens stored in localStorage/sessionStorage (XSS-exfiltratable).", "localStorage.setItem('token', t)"},
	{"postmessage-origin", "postMessage without origin validation or with '*' target.", "postMessage(data, '*')"},
	{"xss-extra-sinks", "Additional HTML injection sinks incl. html/template typed strings.", "template.HTML(userInput)"},
	{"unpinned-action", "GitHub Actions pinned to mutable refs instead of SHAs.", "uses: actions/checkout@main"},
	{"pull-request-target", "pull_request_target trigger risks running untrusted code privileged.", "on: pull_request_target"},
	{"actions-script-injection", "GitHub context interpolated into run: blocks.", "run: echo \"${{ github.event.x }}\""},
	{"pipe-to-shell", "curl|sh style install pipes and insecure curl flags.", "curl -k url | sh"},
	{"unpinned-image", "Container images not pinned to digests.", "FROM ubuntu:latest"},
	{"ci-secret-exposure", "Secrets echoed or inherited in CI workflows.", "secrets: inherit"},
	{"container-privilege", "Privileged containers, host namespaces, root user, hostPath.", "privileged: true"},
	{"dockerfile-remote-add", "Remote ADD/git clone in Dockerfiles (non-reproducible).", "ADD https://x/a.tgz /a"},
	{"dockerfile-user", "Dockerfile runs as root.", "USER root"},
	{"deserialization-gadgets", "Polymorphic/unsafe deserialization gadget chains.", "new XMLDecoder(...).readObject()"},
	{"secret-material", "Credential material in source: URLs with passwords, cloud keys, tokens.", "postgres://user:pass@host/db"},
	{"weak-encoding-crypto", "Base64/hex used where encryption may be intended.", "base64.b64encode(secret)"},
	{"server-timeouts", "HTTP servers/clients without timeout configuration.", "http.ListenAndServe(addr, nil)"},
	{"websocket-origin", "WebSocket CheckOrigin accepting all origins.", "CheckOrigin = func(r) bool { return true }"},
	{"js-common-mistakes", "for...in prototype iteration, parseInt without radix.", "parseInt(x)"},
	{"dynamic-code-loading", "Dynamic module/code loading from user-controlled names.", "importlib.import_module(name)"},
	{"log-injection", "User-controlled data written to logs (log forging).", "log.Print(r.URL)"},
	{"nosql-injection", "MongoDB operators or queries built from request data.", "find({name: req.query.n, $where: '1'})"},
	{"graphql-injection", "GraphQL queries interpolated with user input.", "gql`query { u(id: ${id}) }`"},
	{"email-header-injection", "Email/SMTP headers or commands built from request data.", "msg['Subject'] = req.args['s']"},
	{"unbounded-read", "Unbounded io.ReadAll on potentially large input.", "io.ReadAll(r)"},
	{"client-timeouts", "HTTP clients without Timeout configured.", "&http.Client{}"},
	{"rust-unsafe", "unsafe blocks in Rust code.", "unsafe { *ptr }"},
	{"missing-timeout", "Outbound calls without explicit timeout (requests, TLS server).", "requests.get(url)"},
	{"env-passthrough", "Full environment passed to subprocesses.", "cmd.Env = os.Environ()"},
	{"unsafe-c-functions", "Unbounded C library functions (gets/strcpy/sprintf).", "strcpy(dst, src)"},
	{"iac-exposure", "World-open CIDRs, public ACLs, wildcard IAM, unencrypted storage.", "cidr_blocks = [\"0.0.0.0/0\"]"},
	{"bind-all-interfaces", "Servers bound to all interfaces.", "net.Listen(\"tcp\", \":8080\")"},
	{"cleartext-websocket", "ws:// cleartext WebSocket URLs.", "new WebSocket(\"ws://x/s\")"},
	{"sensitive-data-logging", "Tokens/secrets/passwords written to logs.", "log.Printf(\"token=%s\", t)"},
	{"insecure-protocol", "Cleartext protocols: ftp/telnet/gopher/dict URLs.", "ftp://files/x"},
	{"spreadsheet-formula-injection", "CSV exports with request-controlled cells (=,+,-,@ formulas).", "writerow([request.args['n']])"},
	{"terraform-secret", "Literal credentials in .tf files.", "password = \"...\""},
	{"k8s-committed-secret", "Kubernetes Secret manifests committed to the repo.", "kind: Secret\ndata: ..."},
	{"script-file", "Committed executable scripts (.bat/.ps1/.vbs/etc).", "deploy.bat"},
	{"query-token-exposure", "Authentication tokens exposed in URL query parameters.", "https://api.example.com?token=secret123"},
	{"plaintext-secret-storage", "Plaintext tokens/keys persisted in database schemas or unhashed writes.", "CREATE TABLE users (api_key VARCHAR(255))"},
	{"actions-credential-url", "GitHub Actions workflow secret interpolated into Git remote URL or config.", "https://${{ secrets.PAT }}@github.com/..."},
	{"workflow-force-push", "Destructive unconditional git push force in CI workflow.", "git push --force origin main"},
	{"privileged-service-execution", "Systemd service configured to run as root with broad capabilities.", "User=root"},
	{"shell-script-safety", "Shell script hazards: unquoted rm -rf variables, predictable /tmp, or dynamic eval.", "rm -rf $DIR"},
	{"gin-unhandled-binding", "Unhandled Gin binding errors (Bind/ShouldBind).", "_ = c.BindJSON(&req)"},
	{"gin-wildcard-cors", "Gin CORS configuration with wildcard origins or AllowCredentials.", "cors.Default()"},
	{"gin-missing-recovery", "Gin router initialized with gin.New() without Recovery middleware.", "r := gin.New()"},
	{"gin-unsafe-param-reflection", "Gin route parameter reflected directly in HTTP response.", "c.String(200, c.Param(\"id\"))"},
	{"gin-debug-mode", "Gin debug mode enabled explicitly.", "gin.SetMode(gin.DebugMode)"},
	{"echo-unhandled-binding", "Unhandled Echo binding error.", "_ = c.Bind(&req)"},
	{"echo-wildcard-cors", "Echo CORS configuration allows wildcard origin with credentials.", "AllowOrigins: []string{\"*\"}"},
	{"echo-missing-recovery", "Echo router created without Recover middleware.", "e := echo.New()"},
	{"echo-unsafe-param-reflection", "Echo route parameter reflected directly in HTTP response.", "c.HTML(200, c.Param(\"id\"))"},
	{"chi-unhandled-binding", "Unhandled Chi render.Bind/Decode error.", "_ = render.Bind(r, &req)"},
	{"chi-wildcard-cors", "Chi CORS middleware with wildcard AllowedOrigins and credentials.", "AllowedOrigins: []string{\"*\"}"},
	{"chi-missing-recovery", "Chi router created without middleware.Recoverer.", "r := chi.NewRouter()"},
	{"chi-unsafe-param-reflection", "Chi URLParam reflected directly into response writer.", "w.Write([]byte(chi.URLParam(r, \"id\")))"},
	{"fiber-unhandled-binding", "Unhandled Fiber BodyParser or QueryParser error.", "_ = c.BodyParser(&req)"},
	{"fiber-wildcard-cors", "Fiber CORS middleware with wildcard AllowOrigins and credentials.", "AllowOrigins: \"*\""},
	{"fiber-missing-recovery", "Fiber application created without recover middleware.", "app := fiber.New()"},
	{"fiber-unsafe-param-reflection", "Fiber route parameter reflected directly in response.", "c.SendString(c.Params(\"id\"))"},
	{"http-unhandled-body-read", "Unhandled json.NewDecoder.Decode error on request body.", "_ = json.NewDecoder(r.Body).Decode(&req)"},
	{"http-wildcard-cors", "Wildcard Access-Control-Allow-Origin combined with credentials.", "Access-Control-Allow-Origin: *"},
	{"http-missing-timeouts", "HTTP server started without ReadTimeout/WriteTimeout.", "http.ListenAndServe(\":8080\", nil)"},
	{"http-unsafe-param-reflection", "HTTP request parameter reflected directly in response writer.", "w.Write([]byte(r.PathValue(\"id\")))"},
}

func listRules() error {
	docs := make(map[string]ruleDoc, len(ruleCatalog))
	for _, d := range ruleCatalog {
		docs[d.Name] = d
	}
	fmt.Println("M3TAL Review rules")
	for _, r := range defaultRules("") {
		name := r.Name()
		if d, ok := docs[name]; ok {
			fmt.Printf("  %-32s %s\n", name, d.Description)
		} else {
			fmt.Printf("  %-32s %s\n", name, "Heuristic detector; see README coverage notes.")
		}
	}
	fmt.Println()
	fmt.Println("The code-slop rule covers many per-language checks; see README \"Slop Analyzer Coverage\" for details.")
	return nil
}

func explainRule(name string) error {
	for _, rule := range ruleCatalog {
		if rule.Name == name {
			fmt.Println(rule.Name)
			fmt.Println("  ", rule.Description)
			fmt.Println("   Example:", rule.Example)
			return nil
		}
	}
	for _, r := range defaultRules("") {
		if r.Name() == name {
			fmt.Println(name)
			fmt.Println("  Heuristic detector; suppress with '// m3tal-review: ignore " + name + "' or disable via policy 'rules'.")
			return nil
		}
	}
	return fmt.Errorf("unknown rule %q; run 'm3tal-review list-rules' to see available rules", name)
}

func installHook(force bool) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}
	if err := git.Available(); err != nil {
		return err
	}
	repositoryRoot, err := git.RepositoryRoot(workingDir)
	if err != nil {
		return err
	}
	hooksDir, err := gitHooksPath(repositoryRoot)
	if err != nil {
		return err
	}
	hookPath := filepath.Join(hooksDir, "pre-commit")
	content := "#!/bin/sh\n# Installed by m3tal-review\nm3tal-review review\n"
	if existing, err := os.ReadFile(hookPath); err == nil {
		if strings.Contains(string(existing), "m3tal-review") && !force {
			return fmt.Errorf("pre-commit hook already contains m3tal-review; use --force to replace it")
		}
		if !force {
			return fmt.Errorf("pre-commit hook already exists at %s; use --force to overwrite", displayText(hookPath))
		}
	}
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("create hooks directory: %w", err)
	}
	if err := os.WriteFile(hookPath, []byte(content), 0755); err != nil {
		return fmt.Errorf("write pre-commit hook: %w", err)
	}
	fmt.Println("Installed pre-commit hook:", displayText(hookPath))
	return nil
}

// gitHooksPath resolves the hooks directory via git rev-parse.
func gitHooksPath(repositoryRoot string) (string, error) {
	// "git rev-parse --git-path hooks" handles worktrees and custom git dirs.
	output, err := runCommand(context.Background(), repositoryRoot, "git", "-c", "core.fsmonitor=false", "rev-parse", "--git-path", "hooks")
	if err != nil {
		return "", fmt.Errorf("resolve git hooks path: %w", err)
	}
	hooks := strings.TrimSpace(string(output))
	if !filepath.IsAbs(hooks) {
		hooks = filepath.Join(repositoryRoot, hooks)
	}
	return hooks, nil
}
