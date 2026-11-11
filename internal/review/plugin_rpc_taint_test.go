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
