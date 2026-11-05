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
