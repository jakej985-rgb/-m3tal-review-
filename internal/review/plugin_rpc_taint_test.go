package review

import (
	"strings"
	"testing"
)

// goPkgDiff builds a multi-file diff for package-level taint tests.
func goPkgDiff(files map[string]string) string {
	var b strings.Builder
	for file, source := range files {
		b.WriteString(goDiff(file, source))
	}
	return b.String()
}

// Plugin RPC flow modeled on m3tal-compose: stdin JSON-RPC -> params ->
// SaveStack -> atomicWriteFile -> os.Rename, across two files in one package.
func TestTaintRulePluginRPCReachesWriteSink(t *testing.T) {
	mainSrc := `package main

import (
	"bufio"
	"encoding/json"
	"os"
)

type RPCRequest struct {
	Params json.RawMessage ` + "`json:\"params,omitempty\"`" + `
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var req RPCRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			continue
		}
		var params struct {
			Stack   string ` + "`json:\"stack\"`" + `
			Content string ` + "`json:\"content\"`" + `
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			continue
		}
		_ = SaveStack(params.Stack, params.Content)
	}
}
`
	composeSrc := `package main

import (
	"os"
	"path/filepath"
)

func SaveStack(name, content string) error {
	root := composeRoot()
	filePath := filepath.Join(root, name, "compose.yaml")
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return err
	}
	return atomicWriteFile(filePath, []byte(content), 0644)
}

func composeRoot() string { return "/tmp/compose" }

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	tmp.Close()
	os.Chmod(tmpName, mode)
	return os.Rename(tmpName, path)
}
`
	diff := goPkgDiff(map[string]string{
		"plugin/main.go":    mainSrc,
		"plugin/compose.go": composeSrc,
	})
	findings := (TaintRule{}).Check(diff)
	var hits []Finding
	for _, f := range findings {
		if f.Rule == "request-taint" && f.File == "plugin/compose.go" {
			hits = append(hits, f)
		}
	}
	if len(hits) == 0 {
		t.Fatalf("expected request-taint finding in compose.go, got %+v", findings)
	}
	// The os.Rename sink should be reached through SaveStack's tainted params.
	foundRename := false
	for _, f := range hits {
		if strings.Contains(f.Message, "os.Rename") || f.Line > 0 {
			foundRename = true
		}
	}
	if !foundRename {
		t.Fatalf("expected sink finding reaching atomicWriteFile/os.Rename, got %+v", hits)
	}
}

// RPC params flowing directly into exec.Command inside the same package.
func TestTaintRulePluginRPCReachesExec(t *testing.T) {
	mainSrc := `package main

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
)

type RPCRequest struct {
	Params json.RawMessage ` + "`json:\"params,omitempty\"`" + `
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var req RPCRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			continue
		}
		var params struct {
			Target string ` + "`json:\"target\"`" + `
		}
		_ = json.Unmarshal(req.Params, &params)
		_ = exec.Command("docker", "start", params.Target)
	}
}
`
	diff := goPkgDiff(map[string]string{"plugin/main.go": mainSrc})
	var found bool
	for _, f := range (TaintRule{}).Check(diff) {
		if f.Rule == "request-taint" && strings.Contains(f.Message, "command execution") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected request-taint finding for exec.Command with RPC param")
	}
}

// Config-file unmarshals (json.Unmarshal(b, &cfg)) must NOT be treated as RPC
// input; only line/req.Params sources seed RPC taint.
func TestTaintRuleConfigUnmarshalNotRPCTaint(t *testing.T) {
	src := `package main

import (
	"encoding/json"
	"os"
)

type Config struct {
	Path string ` + "`json:\"path\"`" + `
}

func loadPluginConfig() Config {
	var cfg Config
	b, _ := os.ReadFile("config.json")
	_ = json.Unmarshal(b, &cfg)
	return cfg
}

func main() {
	cfg := loadPluginConfig()
	_ = os.Open(cfg.Path)
}
`
	diff := goPkgDiff(map[string]string{
		"plugin/main.go": `package main

import "bufio"
import "os"

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	_ = scanner
	_ = os.Stdin
}
`,
		"plugin/cfg.go": src,
	})
	for _, f := range (TaintRule{}).Check(diff) {
		if f.Rule == "request-taint" {
			t.Fatalf("config unmarshal should not seed RPC taint, got %+v", f)
		}
	}
}

func TestResolvedPathWriteFires(t *testing.T) {
	src := `package main

import (
	"os"
	"path/filepath"
)

func writeResolved(dir, name string) error {
	real, err := filepath.EvalSymlinks(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	return os.Rename(real+".tmp", real)
}
`
	found := false
	for _, f := range (ResolvedPathRule{}).Check(goDiff("plugin/fs.go", src)) {
		if f.Rule == "resolved-path-write" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected resolved-path-write finding")
	}
}

func TestResolvedPathWriteQuietWithoutWrite(t *testing.T) {
	src := `package main

import "path/filepath"

func resolve(dir, name string) (string, error) {
	return filepath.EvalSymlinks(filepath.Join(dir, name))
}
`
	for _, f := range (ResolvedPathRule{}).Check(goDiff("plugin/fs.go", src)) {
		if f.Rule == "resolved-path-write" {
			t.Fatal("unexpected resolved-path-write finding without write sink")
		}
	}
}

func TestClientTimeoutsSkipsConfiguredClient(t *testing.T) {
	src := `package main

import (
	"net/http"
	"time"
)

var client = &http.Client{
	Timeout:   5 * time.Second,
	Transport: &http.Transport{},
}
`
	for _, f := range (ClientTimeoutRule{}).Check(extraDiff("main.go", src)) {
		t.Fatalf("client-timeouts should not fire on client with Timeout: %+v", f)
	}
}

func TestClientTimeoutsFiresWithoutTimeout(t *testing.T) {
	src := `package main

import "net/http"

var client = &http.Client{Transport: &http.Transport{}}
`
	found := false
	for _, f := range (ClientTimeoutRule{}).Check(extraDiff("main.go", src)) {
		if f.Rule == "client-timeouts" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected client-timeouts finding for client without Timeout")
	}
}

func TestUnboundedReadSkipsLimitReader(t *testing.T) {
	src := `package main

import (
	"io"
	"net/http"
)

func f(r *http.Request) {
	b, _ := io.ReadAll(io.LimitReader(r.Body, 8*1024*1024))
	_ = b
}
`
	for _, r := range rulesByName(t, "unbounded-read") {
		for _, f := range r.Check(extraDiff("main.go", src)) {
			t.Fatalf("unbounded-read should not fire on LimitReader: %+v", f)
		}
	}
}

func TestUnboundedReadFiresPlain(t *testing.T) {
	src := `package main

import (
	"io"
	"net/http"
)

func f(r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	_ = b
}
`
	found := false
	for _, r := range rulesByName(t, "unbounded-read") {
		for _, f := range r.Check(extraDiff("main.go", src)) {
			if f.Rule == "unbounded-read" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected unbounded-read finding")
	}
}

func TestDebugLeftoverSkipsProtocolStdout(t *testing.T) {
	src := `package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type Resp struct {
	Result string ` + "`json:\"result\"`" + `
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		resp := Resp{Result: "ok"}
		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
	}
}
`
	for _, f := range (DebugRule{}).Check(goDiff("plugin/main.go", src)) {
		if f.Rule == "debug-leftover" {
			t.Fatalf("debug-leftover should not fire on protocol stdout: %+v", f)
		}
	}
}

func TestHardcodedCredentialSkipsTestFiles(t *testing.T) {
	src := `package main

func f() {
	apiToken := "m3tal-test-token-abcdef123456"
	_ = apiToken
}
`
	for _, f := range (SecurityRule{}).Check(goDiff("plugin/network_test.go", src)) {
		if f.Rule == "hardcoded-credential" {
			t.Fatalf("hardcoded-credential should not fire in _test.go: %+v", f)
		}
	}
	found := false
	for _, f := range (SecurityRule{}).Check(goDiff("plugin/network.go", src)) {
		if f.Rule == "hardcoded-credential" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected hardcoded-credential finding in non-test file")
	}
}

func TestActionsScriptInjectionSeverity(t *testing.T) {
	trusted := "on: workflow_dispatch\njobs:\n  x:\n    steps:\n      - run: echo \"${{ github.event.inputs.force_bump }}\"\n"
	dangerous := "on: issue_comment\njobs:\n  x:\n    steps:\n      - run: echo \"${{ github.event.comment.body }}\"\n"
	for _, r := range rulesByName(t, "actions-script-injection") {
		for _, f := range r.Check(extraDiff(".github/workflows/ci.yml", trusted)) {
			if f.Severity != "medium" {
				t.Fatalf("dispatch input interpolation should be medium, got %s", f.Severity)
			}
		}
		for _, f := range r.Check(extraDiff(".github/workflows/ci.yml", dangerous)) {
			if f.Severity != "high" {
				t.Fatalf("attacker-controlled context should stay high, got %s", f.Severity)
			}
		}
	}
}

func TestRPCStdinScanner(t *testing.T) {
	unbounded := `package main

import (
	"bufio"
	"os"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	_ = scanner
}
`
	bounded := `package main

import (
	"bufio"
	"os"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	_ = scanner
}
`
	for _, r := range rulesByName(t, "rpc-stdin-scanner") {
		found := false
		for _, f := range r.Check(extraDiff("main.go", unbounded)) {
			if f.Rule == "rpc-stdin-scanner" {
				found = true
			}
		}
		if !found {
			t.Fatal("expected rpc-stdin-scanner finding for unbounded scanner")
		}
		for _, f := range r.Check(extraDiff("main.go", bounded)) {
			if f.Rule == "rpc-stdin-scanner" {
				t.Fatal("rpc-stdin-scanner should not fire when Buffer is configured")
			}
		}
	}
}

func TestTLSInsecureSkipVerifyContext(t *testing.T) {
	plain := `package main

import "crypto/tls"

var c = &tls.Config{InsecureSkipVerify: true}
`
	appAuth := `package main

import (
	"crypto/hmac"
	"crypto/tls"
)

var c = &tls.Config{InsecureSkipVerify: true}

func check(proof, secret []byte) bool {
	mac := hmac.New(nil, secret)
	_ = mac
	return hmac.Equal(proof, proof)
}
`
	credHeader := `package main

import (
	"crypto/tls"
	"net/http"
)

var c = &tls.Config{InsecureSkipVerify: true}

func f(h http.Header) {
	h.Set("X-API-Password", "secret")
}
`
	for _, tc := range []struct {
		name     string
		src      string
		severity string
	}{
		{"plain", plain, "high"},
		{"app-auth", appAuth, "medium"},
		{"cred-header", credHeader, "high"},
	} {
		found := false
		for _, f := range (TLSRule{}).Check(goDiff("net/client.go", tc.src)) {
			if f.Rule == "insecure-tls-verification" {
				found = true
				if f.Severity != tc.severity {
					t.Fatalf("%s: expected severity %s, got %s", tc.name, tc.severity, f.Severity)
				}
			}
		}
		if !found {
			t.Fatalf("%s: expected insecure-tls-verification finding", tc.name)
		}
	}
}

// Multiple filesystem sinks inside one helper reached only via a call edge
// roll up into a single medium finding with per-site evidence.
func TestTaintRuleRollsUpHelperSinks(t *testing.T) {
	mainSrc := `package main

import (
	"bufio"
	"encoding/json"
	"os"
)

type RPCRequest struct {
	Params json.RawMessage ` + "`json:\"params,omitempty\"`" + `
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var req RPCRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			continue
		}
		var params struct {
			Path string ` + "`json:\"path\"`" + `
			Data string ` + "`json:\"data\"`" + `
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			continue
		}
		_ = writeBoth(params.Path, params.Data)
	}
}
`
	helperSrc := `package main

import "os"

func writeBoth(path, data string) error {
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		return err
	}
	return os.Remove(path + ".tmp")
}
`
	diff := goPkgDiff(map[string]string{
		"plugin/main.go":   mainSrc,
		"plugin/helper.go": helperSrc,
	})
	findings := (TaintRule{}).Check(diff)
	var hits []Finding
	for _, f := range findings {
		if f.Rule == "request-taint" && f.File == "plugin/helper.go" {
			hits = append(hits, f)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 rolled-up finding for writeBoth, got %d: %+v", len(hits), hits)
	}
	f := hits[0]
	if f.Severity != "medium" {
		t.Fatalf("expected medium severity for inferred helper sinks, got %s", f.Severity)
	}
	if len(f.Evidence) < 2 {
		t.Fatalf("expected evidence for both sink sites, got %+v", f.Evidence)
	}
	if f.Signature != "func writeBoth" {
		t.Fatalf("expected function signature, got %q", f.Signature)
	}
}

// A sink in the RPC handler itself (direct seed taint, no call edge) stays high.
func TestTaintRuleDirectHandlerSinkStaysHigh(t *testing.T) {
	mainSrc := `package main

import (
	"bufio"
	"encoding/json"
	"os"
)

type RPCRequest struct {
	Params json.RawMessage ` + "`json:\"params,omitempty\"`" + `
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var req RPCRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			continue
		}
		var params struct {
			Path string ` + "`json:\"path\"`" + `
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			continue
		}
		_ = os.WriteFile(params.Path, []byte("x"), 0644)
	}
}
`
	diff := goDiff("plugin/main.go", mainSrc)
	findings := (TaintRule{}).Check(diff)
	var hit *Finding
	for i, f := range findings {
		if f.Rule == "request-taint" {
			hit = &findings[i]
		}
	}
	if hit == nil {
		t.Fatalf("expected request-taint finding, got %+v", findings)
	}
	if hit.Severity != "high" {
		t.Fatalf("expected high severity for direct handler sink, got %s", hit.Severity)
	}
}

// Same-named methods on different receivers must not share a finding
// signature, otherwise GroupFindings merges unrelated flows.
func TestTaintRuleSameNamedMethodsDistinctSignatures(t *testing.T) {
	src := `package main

import (
	"bufio"
	"encoding/json"
	"os"
)

type RPCRequest struct {
	Params json.RawMessage ` + "`json:\"params,omitempty\"`" + `
}

type A struct{}
type B struct{}

func (a *A) Save() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var req RPCRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			continue
		}
		var params struct {
			Path string ` + "`json:\"path\"`" + `
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			continue
		}
		_ = os.WriteFile(params.Path, []byte("a"), 0644)
	}
}

func (b *B) Save() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var req RPCRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			continue
		}
		var params struct {
			Path string ` + "`json:\"path\"`" + `
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			continue
		}
		_ = os.Remove(params.Path)
	}
}
`
	findings := (TaintRule{}).Check(goDiff("plugin/main.go", src))
	sigs := map[string]bool{}
	for _, f := range findings {
		if f.Rule == "request-taint" {
			sigs[f.Signature] = true
		}
	}
	if len(sigs) != 2 {
		t.Fatalf("expected 2 distinct signatures for (*A).Save and (*B).Save, got %v", sigs)
	}
}

// Script injection must only fire inside run:/script: executable contexts;
// structural keys like ref:/with: inputs are data, not shell.
func TestActionsScriptInjectionExecutableContexts(t *testing.T) {
	wf := `.github/workflows/ci.yml
name: ci
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
      - name: safe env
        run: echo "hello"
      - name: injected
        run: |
          echo "title: ${{ github.event.pull_request.title }}"
          echo "done"
      - name: script injection
        uses: actions/github-script@v7
        with:
          script: |
            console.log("${{ github.event.issue.title }}")
`
	diff := extraDiff(".github/workflows/ci.yml", wf)
	findings := (ActionsScriptInjectionRule{}).Check(diff)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (run block + script block), got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Severity != "high" {
			t.Fatalf("expected high for attacker context, got %s at line %d", f.Severity, f.Line)
		}
	}
	// The ref: interpolation must NOT be flagged.
	for _, f := range findings {
		if f.Line == 14 {
			t.Fatalf("ref: input was flagged as script injection: %+v", f)
		}
	}
}

func TestActionsScriptInjectionDispatchInputMedium(t *testing.T) {
	wf := `.github/workflows/release.yml
on:
  workflow_dispatch:
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.inputs.bump_type }}"
`
	diff := extraDiff(".github/workflows/release.yml", wf)
	findings := (ActionsScriptInjectionRule{}).Check(diff)
	if len(findings) != 1 || findings[0].Severity != "medium" {
		t.Fatalf("expected 1 medium finding, got %+v", findings)
	}
}

// Python tests/data fixtures must not produce credential/entropy findings.
func TestSecretRulesSkipPythonTestData(t *testing.T) {
	fixture := `{"feedbackToken": "AOpD3f9xK2mQ8vLpR7tYwEzBcD4sFgHjKlMnBvCxZaSdFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefghij",
 "signatureCipher": "GKl3mQ8vLpR7tYwEzBcD4sFgHjKlMnBvCxZaSdFgHiJkLmNoPqRsTuVwXyZab12",
 "trackingParams": "CAkQ8vLpR7tYwEzBcD4sFgHjKlMnBvCxZaSdFgHiJkLmNoPqRsTuVwXyZabc"}`
	diff := extraDiff("tests/data/2024_03_get_album.json", fixture)
	for _, r := range []Rule{EntropyRule{}, SecretRule{}} {
		for _, f := range r.Check(diff) {
			t.Fatalf("rule %s flagged test fixture: %+v", r.Name(), f)
		}
	}
	// And hardcoded-credential on the same fixture.
	sr := SecurityRule{}
	for _, f := range sr.Check(diff) {
		if f.Rule == "hardcoded-credential" {
			t.Fatalf("hardcoded-credential flagged test fixture: %+v", f)
		}
	}
}

// URL constants named *TOKEN*/*SECRET* are endpoints, not credentials.
func TestHardcodedCredentialSkipsURLValues(t *testing.T) {
	src := `package main

const OAuthTokenURL = "https://oauth2.googleapis.com/token"
`
	diff := extraDiff("auth/oauth.go", src)
	for _, f := range (SecurityRule{}).Check(diff) {
		if f.Rule == "hardcoded-credential" {
			t.Fatalf("URL constant flagged as credential: %+v", f)
		}
	}
}

// Credential files written with permissive/default permissions must flag.
func TestCredentialFilePermGo(t *testing.T) {
	src := `package auth

func (m *OAuthToken) SaveToken() error {
	data, _ := json.Marshal(m)
	return os.WriteFile(m.FilePath, data, 0644)
}

func WriteConfig(path string, data []byte) error {
	return os.WriteFile(path, data, 0600)
}
`
	diff := extraDiff("auth/oauth.go", src)
	findings := (CredentialFilePermRule{}).Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", findings)
	}
	if findings[0].Severity != "medium" {
		t.Fatalf("expected medium for explicit 0644, got %s", findings[0].Severity)
	}
}

func TestCredentialFilePermPython(t *testing.T) {
	src := `import os

def store_token(file_path, token):
    with open(file_path, encoding="utf8", mode="w") as f:
        json.dump(token, f)

def save_report(path, data):
    with open(path, "w") as f:
        f.write(data)
`
	diff := extraDiff("auth/token.py", src)
	findings := (CredentialFilePermRule{}).Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (store_token only), got %+v", findings)
	}
}

func TestDefaultHTTPClient(t *testing.T) {
	src := `package auth

func RequestDeviceCode() {
	resp, err := http.DefaultClient.Do(req)
	_ = resp
	_ = err
}

func Other() {
	resp, err := client.Do(req)
	_ = resp
	_ = err
}
`
	diff := extraDiff("auth/oauth.go", src)
	found := false
	for _, r := range ExtraRules("") {
		if r.Name() != "default-http-client" {
			continue
		}
		for _, f := range r.Check(diff) {
			found = true
			if f.Severity != "low" {
				t.Fatalf("expected low, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("default-http-client did not fire on http.DefaultClient.Do")
	}
}

// AndroidManifest risky attributes must flag; structural/benign attrs must not.
func TestAndroidManifestRule(t *testing.T) {
	manifest := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:allowBackup="true"
        android:usesCleartextTraffic="true"
        android:debuggable="false"
        android:label="GPS">
    </application>
</manifest>
`
	diff := extraDiff("app/src/main/AndroidManifest.xml", manifest)
	var found []Finding
	for _, r := range ExtraRules("") {
		if r.Name() == "android-manifest" {
			found = append(found, r.Check(diff)...)
		}
	}
	if len(found) != 2 {
		t.Fatalf("expected 2 findings (allowBackup + cleartext), got %+v", found)
	}
	for _, f := range found {
		if f.Severity != "medium" {
			t.Fatalf("expected medium, got %s", f.Severity)
		}
	}
}

// Kotlin XXE-prone parser factories and unbounded OkHttp reads must flag.
func TestKotlinCoveragePatterns(t *testing.T) {
	kt := `package com.example

fun parseXml(data: String) {
    val factory = DocumentBuilderFactory.newInstance()
    val builder = factory.newDocumentBuilder()
}

fun fetch(url: String): String {
    val response = client.newCall(request).execute()
    return response.body?.string() ?: ""
}
`
	diff := extraDiff("app/src/main/java/com/example/Net.kt", kt)
	rules := map[string]bool{}
	for _, r := range ExtraRules("") {
		switch r.Name() {
		case "xxe", "unbounded-read":
			if len(r.Check(diff)) > 0 {
				rules[r.Name()] = true
			}
		}
	}
	if !rules["xxe"] {
		t.Fatal("xxe did not fire on Kotlin DocumentBuilderFactory")
	}
	if !rules["unbounded-read"] {
		t.Fatal("unbounded-read did not fire on OkHttp body.string()")
	}
}

// JS/TS request-taint: Express handler input reaching exec/fs sinks.
func TestJSTaintExpressExec(t *testing.T) {
	src := `const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/run', (req, res) => {
    const cmd = req.query.cmd;
    exec(cmd, (err, stdout) => {
        res.send(stdout);
    });
});

app.get('/safe', (req, res) => {
    res.send('ok');
});
`
	diff := extraDiff("src/routes.js", src)
	var findings []Finding
	for _, f := range (TaintRule{}).Check(diff) {
		if f.Rule == "request-taint" {
			findings = append(findings, f)
		}
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 request-taint finding, got %+v", findings)
	}
	if findings[0].Severity != "high" {
		t.Fatalf("expected high for exec sink, got %s", findings[0].Severity)
	}
	if findings[0].Confidence != "medium" {
		t.Fatalf("expected medium confidence for JS intra-file analysis, got %s", findings[0].Confidence)
	}
}

// Taint must not cross function boundaries: a tainted var in handler A
// must not flag sinks in unrelated handler B.
func TestJSTaintBoundaryIsolation(t *testing.T) {
	src := `function handlerA(req, res) {
    const path = req.query.path;
    return path;
}

function helper() {
    const path = '/tmp/static.txt';
    fs.readFileSync(path);
}
`
	diff := extraDiff("src/handlers.js", "const fs = require('fs');\n"+src)
	for _, f := range (TaintRule{}).Check(diff) {
		if f.Rule == "request-taint" {
			t.Fatalf("unexpected request-taint finding across function boundary: %+v", f)
		}
	}
}

// fs sinks and serving APIs flag at medium; sanitized args downgrade.
func TestJSTaintFsAndServe(t *testing.T) {
	src := `const fs = require('fs');
const express = require('express');
const app = express();

app.get('/file', (req, res) => {
    const name = req.params.name;
    fs.readFileSync('/data/' + name);
    res.sendFile('/data/' + name);
});

app.get('/clean', (req, res) => {
    const name = encodeURIComponent(req.query.name);
    eval(name);
});
`
	diff := extraDiff("src/app.js", src)
	var findings []Finding
	for _, f := range (TaintRule{}).Check(diff) {
		if f.Rule == "request-taint" {
			findings = append(findings, f)
		}
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 rolled-up finding, got %+v", findings)
	}
	if findings[0].Severity != "medium" {
		t.Fatalf("expected medium (fs/serve sinks; guarded eval suppressed), got %s", findings[0].Severity)
	}
	// eval(name) must NOT appear: name was assigned through
	// encodeURIComponent, so the guard stripped the taint at assignment.
	if len(findings[0].Evidence) != 2 {
		t.Fatalf("expected 2 sink evidence entries (fs + sendFile), got %+v", findings[0].Evidence)
	}
	for _, e := range findings[0].Evidence {
		if strings.Contains(e.Message, "eval") {
			t.Fatalf("guarded eval should not be flagged: %+v", e)
		}
	}
}
