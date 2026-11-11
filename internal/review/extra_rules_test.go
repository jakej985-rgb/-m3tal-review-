package review

import (
	"strings"
	"testing"
)

func extraDiff(file, body string) string {
	return "diff --git a/" + file + " b/" + file + "\nnew file mode 100644\n--- /dev/null\n+++ b/" + file + "\n@@ -0,0 +1," + itoa(countLines(body)) + " @@\n" + prefixLines(body)
}

func countLines(s string) int {
	n := 0
	for _, c := range s {
		if c == '\n' {
			n++
		}
	}
	if !strings.HasSuffix(s, "\n") {
		n++
	}
	return n
}

func prefixLines(s string) string {
	out := ""
	for _, l := range splitLines(s) {
		out += "+" + l + "\n"
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == '\n' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func rulesByName(t *testing.T, names ...string) []Rule {
	t.Helper()
	all := ExtraRules("/tmp/nonexistent-root")
	var out []Rule
	for _, r := range all {
		for _, n := range names {
			if r.Name() == n {
				out = append(out, r)
			}
		}
	}
	if len(out) != len(names) {
		t.Fatalf("missing rules, got %d want %d", len(out), len(names))
	}
	return out
}

func hasFinding(findings []Finding, rule string) bool {
	for _, f := range findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestExtraRulesDetections(t *testing.T) {
	cases := []struct {
		rule string
		file string
		body string
	}{
		{"ssrf", "main.go", "package main\nimport \"net/http\"\nfunc h(w http.ResponseWriter, r *http.Request) {\n\thttp.Get(r.URL.Query().Get(\"u\"))\n}\n"},
		{"command-injection", "main.py", "import subprocess, os\ndef f():\n    subprocess.call(\"ls \" + os.environ[\"D\"], shell=True)\n"},
		{"open-redirect", "app.py", "from flask import redirect, request\n@app.route('/')\ndef i():\n    return redirect(request.args.get('next'))\n"},
		{"template-injection", "app.py", "from flask import render_template_string, request\ndef i():\n    return render_template_string(request.args.get('t'))\n"},
		{"prototype-pollution", "app.js", "function f(req, out) {\n  Object.assign(out, req.body)\n}\n"},
		{"archive-extraction", "app.py", "import zipfile\ndef f(z):\n    zipfile.ZipFile(z).extractall('/tmp/x')\n"},
		{"xxe", "Parser.java", "class P {\n  void f() throws Exception {\n    javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder();\n  }\n}\n"},
		{"jwt-misuse", "auth.py", "import jwt\ndef f(t):\n    return jwt.decode(t, key, algorithms=['none'])\n"},
		{"hardcoded-session-secret", "config.go", "package main\nconst JWT_SECRET = \"supersecretvalue123\"\n"},
		{"tls-verification", "main.js", "const https = require('https');\nconst opts = { rejectUnauthorized: false };\n"},
		{"timing-unsafe-compare", "auth.py", "def f(password, expected_password):\n    return password == expected_password\n"},
		{"insecure-randomness", "main.js", "function t() {\n  return Math.random()\n}\n"},
		{"web-storage-secrets", "app.js", "function f(t) {\n  localStorage.setItem('auth_token', t)\n}\n"},
		{"postmessage-origin", "app.js", "window.addEventListener('message', function(e) { console.log(e.data) })\n"},
		{"xss-extra-sinks", "app.js", "function f(el, html) {\n  el.insertAdjacentHTML('beforeend', html)\n}\n"},
		{"unpinned-action", ".github/workflows/ci.yml", "name: ci\non: push\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n"},
		{"pull-request-target", ".github/workflows/ci.yml", "on:\n  pull_request_target:\njobs:\n  x:\n    runs-on: ubuntu-latest\n"},
		{"actions-script-injection", ".github/workflows/ci.yml", "on: push\njobs:\n  x:\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n"},
		{"pipe-to-shell", "install.sh", "#!/bin/sh\ncurl -fsSL https://x.test/i.sh | sh\n"},
		{"container-privilege", "docker-compose.yml", "services:\n  app:\n    privileged: true\n"},
		{"dockerfile-remote-add", "Dockerfile", "FROM alpine:3.19\nADD https://x.test/a.tar /a\n"},
		{"deserialization-gadgets", "Parser.java", "class P {\n  void f(String s) throws Exception {\n    Object o = new XMLDecoder(new ByteArrayInputStream(s.getBytes())).readObject();\n  }\n}\n"},
		{"secret-material", "deploy.sh", "DATABASE_URL=postgres://admin:hunter2secret@db.internal:5432/app\n"},
		{"weak-encoding-crypto", "crypt.py", "import base64\ndef f(d):\n    return base64.b64encode(d)\n"},
		{"websocket-origin", "ws.go", "package main\nfunc h(c *websocket.Conn) {\n\tupgrader.CheckOrigin = func(r *http.Request) bool { return true }\n}\n"},
		{"dockerfile-user", "Dockerfile", "FROM alpine:3.19\nUSER root\nCMD [\"sh\"]\n"},
		{"js-common-mistakes", "app.js", "function f(o) {\n  for (k in o) { console.log(k) }\n  return parseInt(o.n)\n}\n"},
		{"dynamic-code-loading", "loader.py", "import importlib\ndef f(name):\n    return importlib.import_module(name)\n"},
		{"log-injection", "app.py", "import logging, request\ndef f():\n    logging.info('got ' + request.args.get('q'))\n"},
		{"nosql-injection", "app.js", "db.users.find({ name: req.query.name, $where: '1==1' })\n"},
		{"graphql-injection", "q.js", "const q = gql`query { user(id: ${uid}) { name } }`\n"},
		{"email-header-injection", "mail.py", "def f(to):\n    msg['Subject'] = 'Hi ' + request.args.get('n')\n"},
		{"unbounded-read", "main.go", "package main\nimport \"io\"\nfunc f(r io.Reader) []byte {\n\tb, _ := io.ReadAll(r)\n\treturn b\n}\n"},
		// client-timeouts moved to ClientTimeoutRule (see plugin_rpc_taint_test.go).
		{"rust-unsafe", "lib.rs", "fn f(p: *const u8) -> u8 {\n    unsafe { *p }\n}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			diff := extraDiff(tc.file, tc.body)
			for _, r := range rulesByName(t, tc.rule) {
				if !hasFinding(r.Check(diff), tc.rule) {
					t.Errorf("rule %s did not fire on %s", tc.rule, tc.file)
				}
			}
		})
	}
}

func TestSecretFileRule(t *testing.T) {
	diff := extraDiff("config/.env.production", "SECRET=abc\n")
	r := rulesByName(t, "secret-file")[0]
	if !hasFinding(r.Check(diff), "secret-file") {
		t.Fatal("secret-file did not flag .env.production")
	}
	diff2 := extraDiff("main.go", "package main\n")
	if hasFinding(r.Check(diff2), "secret-file") {
		t.Fatal("secret-file flagged normal file")
	}
}

func TestUnpinnedActionSkipsSHA(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	diff := extraDiff(".github/workflows/ci.yml", "on: push\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@"+sha+"\n")
	r := rulesByName(t, "unpinned-action")[0]
	if hasFinding(r.Check(diff), "unpinned-action") {
		t.Fatal("pinned SHA action flagged")
	}
}

func TestMissingTimeoutAndEnvPassthrough(t *testing.T) {
	cases := []struct {
		rule string
		file string
		body string
	}{
		{"missing-timeout", "app.py", "import requests\ndef f(u):\n    return requests.get(u)\n"},
		{"missing-timeout", "main.go", "package main\nimport \"net/http\"\nfunc s() {\n\thttp.ListenAndServeTLS(\":443\", \"c\", \"k\", nil)\n}\n"},
		{"env-passthrough", "main.go", "package main\nimport \"os/exec\"\nfunc f() {\n\tcmd := exec.Command(\"ls\")\n\tcmd.Env = os.Environ()\n}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.rule+"/"+tc.file, func(t *testing.T) {
			diff := extraDiff(tc.file, tc.body)
			for _, r := range rulesByName(t, tc.rule) {
				if !hasFinding(r.Check(diff), tc.rule) {
					t.Errorf("rule %s did not fire on %s", tc.rule, tc.file)
				}
			}
		})
	}
}

func TestUnstagedReadyDetectors(t *testing.T) {
	cases := []struct {
		rule string
		file string
		body string
	}{
		{"xss-extra-sinks", "app.js", "function f(h) {\n  document.write(h)\n}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			diff := extraDiff(tc.file, tc.body)
			for _, r := range rulesByName(t, tc.rule) {
				if !hasFinding(r.Check(diff), tc.rule) {
					t.Errorf("rule %s did not fire on %s", tc.rule, tc.file)
				}
			}
		})
	}
}

func TestWave7Detectors(t *testing.T) {
	cases := []struct {
		rule string
		file string
		body string
	}{
		{"unsafe-c-functions", "util.c", "#include <stdio.h>\nvoid f(char *p) {\n    char b[16];\n    strcpy(b, p);\n}\n"},
		{"iac-exposure", "main.tf", "resource \"aws_security_group\" \"x\" {\n  ingress {\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n"},
		{"postmessage-origin", "app.js", "window.postMessage(data, '*')\n"},
		{"dynamic-code-loading", "app.php", "<?php\ncall_user_func($_GET['fn']);\n"},
		{"secret-material", "keys.txt", "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n"},
	}
	for _, tc := range cases {
		t.Run(tc.rule+"/"+tc.file, func(t *testing.T) {
			diff := extraDiff(tc.file, tc.body)
			for _, r := range rulesByName(t, tc.rule) {
				if !hasFinding(r.Check(diff), tc.rule) {
					t.Errorf("rule %s did not fire on %s", tc.rule, tc.file)
				}
			}
		})
	}
}

func TestWave8Detectors(t *testing.T) {
	cases := []struct {
		rule string
		file string
		body string
	}{
		{"weak-crypto-params", "h.py", "import hashlib\ndef f(d):\n    return hashlib.md5(d).hexdigest()\n"},
		{"jwt-misuse", "auth.py", "import jwt\ndef f(t):\n    return jwt.decode(t, key, options={\"verify_signature\": False})\n"},
		{"deserialization-gadgets", "P.java", "class P {\n  void f(String s) {\n    XStream xs = new XStream();\n  }\n}\n"},
		{"secret-material", "k.txt", "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaa\n"},
		{"tls-verification", "c.py", "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\nctx.check_hostname = False\n"},
		{"bind-all-interfaces", "srv.go", "package main\nimport \"net\"\nfunc f() {\n\tnet.Listen(\"tcp\", \":8080\")\n}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.rule+"/"+tc.file, func(t *testing.T) {
			diff := extraDiff(tc.file, tc.body)
			for _, r := range rulesByName(t, tc.rule) {
				if !hasFinding(r.Check(diff), tc.rule) {
					t.Errorf("rule %s did not fire on %s", tc.rule, tc.file)
				}
			}
		})
	}
}

func TestWave910Detectors(t *testing.T) {
	cases := []struct {
		rule string
		file string
		body string
	}{
		{"unsafe-code", "link.go", "package main\nimport _ \"unsafe\"\n//go:linkname nanotime runtime.nanotime\nfunc nanotime() int64\n"},
		{"unsafe-code", "n.py", "import ctypes\ndef f(p):\n    return ctypes.string_at(p)\n"},
		{"cleartext-websocket", "app.js", "const ws = new WebSocket(\"ws://example.com/socket\")\n"},
		{"secret-material", "k.txt", "dop_v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"},
		{"container-privilege", "deploy.yml", "securityContext:\n  runAsUser: 0\n"},
	}
	for _, tc := range cases {
		t.Run(tc.rule+"/"+tc.file, func(t *testing.T) {
			diff := extraDiff(tc.file, tc.body)
			for _, r := range rulesByName(t, tc.rule) {
				if !hasFinding(r.Check(diff), tc.rule) {
					t.Errorf("rule %s did not fire on %s", tc.rule, tc.file)
				}
			}
		})
	}
}

func TestPhaseADetectors(t *testing.T) {
	cases := []struct {
		rule string
		file string
		body string
	}{
		{"xss-extra-sinks", "v.go", "package main\nimport \"html/template\"\nfunc f() template.HTML {\n\treturn template.HTML(\"<b>\")\n}\n"},
		{"xss-extra-sinks", "v.blade.php", "<div>{!! $userInput !!}</div>\n"},
		{"template-injection", "v.php", "<?php\n$tpl->render($_GET['page']);\n"},
		{"email-header-injection", "m.py", "import smtplib, request\ndef f():\n    smtplib.SMTP('h').sendmail('a@b.c', request.args.get('t'), 'x')\n"},
		{"secret-material", ".netrc", "machine example.com login deploy password hunter2abc\n"},
		{"terraform-secret", "main.tf", "resource \"aws_db_instance\" \"db\" {\n  password = \"Sup3rSecretValue\"\n}\n"},
		{"k8s-committed-secret", "sec.yaml", "apiVersion: v1\nkind: Secret\nmetadata:\n  name: creds\ndata:\n  password: aHVudGVyMg==\n"},
		{"tls-verification", "c.go", "package main\nimport \"crypto/tls\"\nvar c = &tls.Config{MinVersion: tls.VersionTLS10}\n"},
		{"pipe-to-shell", "fetch.sh", "#!/bin/sh\ncurl -k https://x.test/i.sh | sh\n"},
		{"cookie-flags", "app.py", "def f(r):\n    r.set_cookie('session', t, remember=True)\n"},
		{"sensitive-data-logging", "main.go", "package main\nimport \"log\"\nfunc f(t string) {\n\tlog.Printf(\"token=%s\", t)\n}\n"},
		{"insecure-protocol", "cfg.py", "URL = \"ftp://files.example.com/pub\"\n"},
		{"injection-other", "h.php", "<?php\nheader('Location: ' . $_GET['next']);\n"},
	}
	for _, tc := range cases {
		t.Run(tc.rule+"/"+tc.file, func(t *testing.T) {
			diff := extraDiff(tc.file, tc.body)
			for _, r := range rulesByName(t, tc.rule) {
				if !hasFinding(r.Check(diff), tc.rule) {
					t.Errorf("rule %s did not fire on %s", tc.rule, tc.file)
				}
			}
		})
	}
}

func TestSpreadsheetFormulaInjection(t *testing.T) {
	cases := []struct {
		file string
		body string
	}{
		{"export.py", "import csv, request\ndef f():\n    w = csv.writer(r)\n    w.writerow([request.args.get('name')])\n"},
		{"export.js", "const out = csvStringify(rows.map(r => req.query.name))\n"},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			diff := extraDiff(tc.file, tc.body)
			for _, r := range rulesByName(t, "spreadsheet-formula-injection") {
				if !hasFinding(r.Check(diff), "spreadsheet-formula-injection") {
					t.Errorf("rule did not fire on %s", tc.file)
				}
			}
		})
	}
}

func TestPhaseBDetectors(t *testing.T) {
	cases := []struct {
		rule string
		file string
		body string
	}{
		{"dynamic-code-loading", "d.go", "package main\nimport \"net/http\"\nfunc f(w http.ResponseWriter, r *http.Request) {\n\t_ = r.FormValue(\"x\")\n\tm := reflect.ValueOf(1).MethodByName(r.FormValue(\"m\"))\n\t_ = m\n}\n"},
		{"unsafe-code", "s.go", "package main\nimport \"syscall\"\nfunc f() {\n\tsyscall.Exec(\"/bin/sh\", nil, nil)\n}\n"},
		{"unsafe-code", "t.py", "import tempfile\ndef f():\n    return tempfile.mktemp()\n"},
		{"injection-other", "p.py", "import os, request\ndef f():\n    os.chmod(request.args[\"f\"], 0o777)\n"},
		{"dynamic-code-loading", "r.js", "const re = new RegExp(req.query.pattern)\n"},
		{"dynamic-code-loading", "P.java", "class P {\n  void f() {\n    new ProcessImpl(new String[]{\"cmd\"});\n  }\n}\n"},
		{"container-privilege", "pod.yml", "spec:\n  hostPath:\n    path: /etc\n  serviceAccountName: default\n"},
		{"iac-exposure", "iam.tf", "resource \"aws_iam_policy\" \"p\" {\n  policy = jsonencode({\n    Action = \"*\"\n  })\n}\n"},
		{"ci-secret-exposure", ".github/workflows/reusable.yml", "jobs:\n  call:\n    uses: org/repo/.github/workflows/x.yml@main\n    secrets: inherit\n"},
	}
	for _, tc := range cases {
		t.Run(tc.rule+"/"+tc.file, func(t *testing.T) {
			diff := extraDiff(tc.file, tc.body)
			for _, r := range rulesByName(t, tc.rule) {
				if !hasFinding(r.Check(diff), tc.rule) {
					t.Errorf("rule %s did not fire on %s", tc.rule, tc.file)
				}
			}
		})
	}
}

func TestPhase1PairedPositiveNegativeFixtures(t *testing.T) {
	type fixtureCase struct {
		rule     string
		file     string
		positive string // must trigger rule
		negative string // must NOT trigger rule
	}

	cases := []fixtureCase{
		{
			rule:     "secret-file",
			file:     ".env",
			positive: "DB_PASS=production123\n",
			negative: "# normal file content",
		},
		{
			rule:     "websocket-origin",
			file:     "ws.go",
			positive: "package main\nimport \"net/http\"\nfunc h() {\n\tupgrader.CheckOrigin = func(r *http.Request) bool { return true }\n}\n",
			negative: "package main\nimport \"net/http\"\nfunc h() {\n\tupgrader.CheckOrigin = func(r *http.Request) bool { return allowedHosts[r.Header.Get(\"Origin\")] }\n}\n",
		},
		{
			rule:     "websocket-origin",
			file:     "server.js",
			positive: "const io = require('socket.io')(server, { cors: { origin: '*' } });\n",
			negative: "const io = require('socket.io')(server, { cors: { origin: ['https://example.com'] } });\n",
		},
		{
			rule:     "websocket-origin",
			file:     "app.py",
			positive: "class SocketHandler(websocket.WebSocketHandler):\n    def check_origin(self, origin):\n        return True\n",
			negative: "class SocketHandler(websocket.WebSocketHandler):\n    def check_origin(self, origin):\n        return origin == 'https://trusted.domain'\n",
		},
		{
			rule:     "timing-unsafe-compare",
			file:     "auth.go",
			positive: "package auth\nfunc Verify(token, expectedToken string) bool {\n\treturn token == expectedToken\n}\n",
			negative: "package auth\nimport \"crypto/subtle\"\nfunc Verify(token, expectedToken string) bool {\n\treturn subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) == 1\n}\n",
		},
		{
			rule:     "timing-unsafe-compare",
			file:     "auth.py",
			positive: "def verify_api_key(api_key, expected_key):\n    return api_key == expected_key\n",
			negative: "import hmac\ndef verify_api_key(api_key, expected_key):\n    return hmac.compare_digest(api_key, expected_key)\n",
		},
		{
			rule:     "timing-unsafe-compare",
			file:     "auth.js",
			positive: "function verifySecret(secret, expectedSecret) {\n  return secret === expectedSecret;\n}\n",
			negative: "const crypto = require('crypto');\nfunction verifySecret(secret, expectedSecret) {\n  return crypto.timingSafeEqual(Buffer.from(secret), Buffer.from(expectedSecret));\n}\n",
		},
		{
			rule:     "web-storage-secrets",
			file:     "storage.js",
			positive: "function saveAuth(authToken) {\n  localStorage.setItem('auth_token', authToken);\n}\n",
			negative: "function saveTheme(theme) {\n  localStorage.setItem('theme-key', theme);\n  sessionStorage.setItem('sidebar_collapsed', 'true');\n}\n",
		},
		{
			rule:     "query-token-exposure",
			file:     "client.js",
			positive: "const ws = new WebSocket('wss://api.example.com/stream?token=synthetic_token_123456');\n",
			negative: "const ws = new WebSocket('wss://api.example.com/stream?ticket=single_use_ticket_nonce');\n",
		},
		{
			rule:     "plaintext-secret-storage",
			file:     "schema.sql",
			positive: "CREATE TABLE api_clients (\n  id INT PRIMARY KEY,\n  api_key VARCHAR(255) NOT NULL\n);\n",
			negative: "CREATE TABLE api_clients (\n  id INT PRIMARY KEY,\n  api_key_hash VARCHAR(64) NOT NULL,\n  salt VARCHAR(32) NOT NULL\n);\n",
		},
		{
			rule:     "actions-credential-url",
			file:     ".github/workflows/sync.yml",
			positive: "name: Sync\non: push\njobs:\n  run:\n    steps:\n      - run: git clone https://${{ secrets.PAT }}@github.com/org/repo.git\n",
			negative: "name: Sync\non: push\njobs:\n  run:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          token: ${{ secrets.PAT }}\n",
		},
		{
			rule:     "workflow-force-push",
			file:     ".github/workflows/deploy.yml",
			positive: "name: Deploy\non: push\njobs:\n  deploy:\n    steps:\n      - run: git push --force origin production\n",
			negative: "name: Deploy\non: push\njobs:\n  deploy:\n    steps:\n      - run: git push origin production\n",
		},
		{
			rule:     "privileged-service-execution",
			file:     "daemon.service",
			positive: "[Service]\nUser=root\nCapabilityBoundingSet=CAP_SYS_ADMIN\n",
			negative: "[Service]\nUser=appdaemon\nDynamicUser=yes\nProtectSystem=strict\nProtectHome=true\n",
		},
		{
			rule:     "shell-script-safety",
			file:     "deploy.sh",
			positive: "#!/bin/bash\nrm -rf $TARGET_DIR\neval $USER_INPUT\n",
			negative: "#!/bin/bash\nset -euo pipefail\nrm -rf \"${TARGET_DIR}\"\ntmpfile=$(mktemp)\n",
		},
	}

	for _, tc := range cases {
		t.Run("positive/"+tc.rule+"/"+tc.file, func(t *testing.T) {
			diff := extraDiff(tc.file, tc.positive)
			ruleList := rulesByName(t, tc.rule)
			if len(ruleList) == 0 {
				t.Fatalf("rule %q not found", tc.rule)
			}
			found := false
			for _, r := range ruleList {
				if hasFinding(r.Check(diff), tc.rule) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected rule %q to fire on positive fixture in %s", tc.rule, tc.file)
			}
		})

		t.Run("negative/"+tc.rule+"/"+tc.file, func(t *testing.T) {
			file := tc.file
			if tc.rule == "secret-file" {
				file = ".env.example" // safe template naming convention
			}
			diff := extraDiff(file, tc.negative)
			ruleList := rulesByName(t, tc.rule)
			if len(ruleList) == 0 {
				t.Fatalf("rule %q not found", tc.rule)
			}
			for _, r := range ruleList {
				if hasFinding(r.Check(diff), tc.rule) {
					t.Errorf("expected rule %q NOT to fire on negative fixture in %s", tc.rule, file)
				}
			}
		})
	}
}

func TestUnpinnedActionDistinctSignatures(t *testing.T) {
	r := rulesByName(t, "unpinned-action")[0]
	content := "name: ci\non: push\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-go@v5\n      - uses: softprops/action-gh-release@v2\n"
	findings := r.Check(extraDiff(".github/workflows/ci.yml", content))
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings for 3 unpinned uses, got %d: %+v", len(findings), findings)
	}
	sigs := map[string]bool{}
	for _, f := range findings {
		if f.Signature == "" {
			t.Fatalf("expected signature from match, got empty: %+v", f)
		}
		sigs[f.Signature] = true
	}
	if len(sigs) != 3 {
		t.Fatalf("expected 3 distinct signatures, got %v", sigs)
	}
}
