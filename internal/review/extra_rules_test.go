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
		{"tls-verification", "main.go", "package main\nimport \"crypto/tls\"\nvar c = &tls.Config{InsecureSkipVerify: true}\n"},
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
		{"client-timeouts", "main.go", "package main\nimport \"net/http\"\nvar c = &http.Client{}\n"},
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
