package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestLoadBaseline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.txt")
	if err := os.WriteFile(path, []byte("abc123\ndef456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := loadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if !set["abc123"] || !set["def456"] || len(set) != 2 {
		t.Fatalf("set = %v", set)
	}
	jpath := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(jpath, []byte(`["aaa","bbb"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err = loadBaseline(jpath)
	if err != nil || !set["aaa"] || len(set) != 2 {
		t.Fatalf("json set = %v err=%v", set, err)
	}
	// Symlink rejected.
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(path, link); err == nil {
		if _, err := loadBaseline(link); err == nil {
			t.Fatal("symlink baseline accepted")
		}
	}
}

func TestFilterBaseline(t *testing.T) {
	findings := []review.Finding{
		{ID: "aaa", Rule: "r"},
		{ID: "bbb", Rule: "r"},
		{ID: "", Rule: "r"},
	}
	out := filterBaseline(findings, map[string]bool{"aaa": true})
	if len(out) != 2 || out[0].ID != "bbb" {
		t.Fatalf("out = %+v", out)
	}
}

func TestPostCheckRunRequiresEnv(t *testing.T) {
	for _, k := range []string{"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_REPOSITORY", "GITHUB_SHA"} {
		t.Setenv(k, "")
	}
	if err := postCheckRun(nil, ""); err == nil {
		t.Fatal("expected error without GitHub env configuration")
	}
}

func TestSarifOutputHasRequiredFields(t *testing.T) {
	out, err := formatFindingsSarif([]review.Finding{
		{Rule: "r1", Severity: "high", Category: "security", File: "a.go", Line: 3, Message: "m", Remediation: "fix"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"2.1.0"`, `"tool"`, `"driver"`, `"results"`, `"physicalLocation"`, `"ruleId"`} {
		if !strings.Contains(out, want) {
			t.Errorf("SARIF output missing %s", want)
		}
	}
}

func TestHistoryShowFindsReport(t *testing.T) {
	dir := t.TempDir()
	reports := filepath.Join(dir, ".m3tal-review", "reports")
	if err := os.MkdirAll(reports, 0o755); err != nil {
		t.Fatal(err)
	}
	rep := review.Report{
		RunID:     "abc123",
		Scope:     "review",
		Branch:    "main",
		CommitSHA: "deadbeef",
		Passed:    true,
		Findings:  []review.Finding{{Rule: "r", Severity: "low", File: "a.go", Line: 1, Message: "m"}},
	}
	if err := review.WriteReport(filepath.Join(reports, "abc123.json"), rep); err != nil {
		t.Fatal(err)
	}
	// Prefix lookup resolves the full ID.
	if err := commandHistoryShow(dir, "abc"); err != nil {
		t.Fatalf("history show failed: %v", err)
	}
	if err := commandHistoryShow(dir, "zzz"); err == nil {
		t.Fatal("expected error for unknown run ID")
	}
	if err := commandHistoryShow(dir, "../etc"); err == nil {
		t.Fatal("expected error for path traversal run ID")
	}
}

func TestUserConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	cfgDir := filepath.Join(dir, "m3tal-review")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgJSON := `{"profile":"security","fail_on":"high","format":"json","skip":["slop"],"only":["ssrf"]}`
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadUserConfig()
	if err != nil {
		t.Fatal(err)
	}
	opts, err := parseReviewOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	applyUserConfig(&opts, cfg)
	if opts.Profile != "security" || opts.FailOn != "high" || opts.Format != "json" {
		t.Fatalf("config not applied: %+v", opts)
	}
	if len(opts.Only) != 1 || opts.Only[0] != "ssrf" || len(opts.Skip) != 1 || opts.Skip[0] != "slop" {
		t.Fatalf("rule filters not applied: %+v", opts)
	}

	// Explicit CLI flags override config.
	opts2, err := parseReviewOptions([]string{"--profile", "slop", "--format", "text"})
	if err != nil {
		t.Fatal(err)
	}
	applyUserConfig(&opts2, cfg)
	if opts2.Profile != "slop" || opts2.Format != "text" {
		t.Fatalf("CLI flags did not override config: %+v", opts2)
	}
	if opts2.FailOn != "high" {
		t.Fatalf("unset flag should take config value, got %q", opts2.FailOn)
	}
}

func TestUserConfigAuditDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	cfgDir := filepath.Join(dir, "m3tal-review")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgJSON := `{"profile":"security","fail_on":"medium","format":"json","skip":["slop"]}`
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadUserConfig()
	if err != nil {
		t.Fatal(err)
	}
	opts, err := parseAuditOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	applyUserConfigAudit(&opts, cfg)
	// security profile is review-only; audit keeps its own default.
	if opts.Profile != "fast" {
		t.Fatalf("review-only profile leaked into audit: %q", opts.Profile)
	}
	if opts.FailOn != "medium" || opts.Format != "json" || len(opts.Skip) != 1 {
		t.Fatalf("config not applied to audit: %+v", opts)
	}
}

func TestAuditCacheRoundTrip(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("M3TAL_NO_AUDIT_CACHE", "")
	rules := []review.Rule{review.TodoRule{}}
	c := newAuditCache("/tmp/repo-a", rules, true)
	if c == nil {
		t.Skip("cache unavailable in this environment")
	}
	diff := "diff --git a/x.go b/x.go\n--- a/x.go\n+++ b/x.go\n@@ -0,0 +1 @@\n+// TODO: fix\n"
	findings := []review.Finding{{Rule: "todo-marker", Severity: "low", File: "x.go", Line: 1, Message: "m"}}
	c.put(diff, findings)
	c.flush()

	c2 := newAuditCache("/tmp/repo-a", rules, true)
	got, ok := c2.get(diff)
	if !ok || len(got) != 1 || got[0].Message != "m" {
		t.Fatalf("cache round-trip failed: %+v", got)
	}
	// Different rule set must miss.
	c3 := newAuditCache("/tmp/repo-a", []review.Rule{review.DebugRule{}}, true)
	if _, ok := c3.get(diff); ok {
		t.Fatal("cache hit across different rule sets")
	}
	// Timeout findings must not be cached.
	diff2 := diff + "diff --git a/y.go b/y.go\n"
	c.put(diff2, []review.Finding{{Rule: "x-timeout"}})
	if _, ok := c.get(diff2); ok {
		t.Fatal("timeout finding was cached")
	}
}
