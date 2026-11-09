package review

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupLintTestRepo(t *testing.T) string {
	t.Helper()

	repoDir := t.TempDir()

	if err := os.WriteFile(
		filepath.Join(repoDir, "go.mod"),
		[]byte("module linttest\n\ngo 1.23\n"),
		0644,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		filepath.Join(repoDir, "main.go"),
		[]byte("package main\n\nfunc main() {\n\tprintln(\"hello\")\n}\n"),
		0644,
	); err != nil {
		t.Fatal(err)
	}

	return repoDir
}

func TestLintRulePassesCleanProject(t *testing.T) {
	repoDir := setupLintTestRepo(t)

	findings := (LintRule{RepositoryRoot: repoDir}).Check("")

	if len(findings) != 0 {
		t.Fatalf("Check() returned %d findings, want 0: %+v", len(findings), findings)
	}
}

func TestLintRuleFindsUnformattedFile(t *testing.T) {
	repoDir := setupLintTestRepo(t)

	mainPath := filepath.Join(repoDir, "main.go")
	if err := os.WriteFile(
		mainPath,
		[]byte("package main\nfunc main(){println(\"hello\")}\n"),
		0644,
	); err != nil {
		t.Fatal(err)
	}

	findings := (LintRule{RepositoryRoot: repoDir}).Check("")

	found := false
	for _, finding := range findings {
		if finding.Rule == "repository-lint" &&
			finding.File == "main.go" &&
			finding.Message == "File is not formatted; run gofmt" {
			found = true
		}
	}

	if !found {
		t.Errorf("formatting finding not found: %+v", findings)
	}
}

func TestLintRuleReportsGoVetFileAndLine(t *testing.T) {
	repoDir := setupLintTestRepo(t)

	mainPath := filepath.Join(repoDir, "main.go")
	source := "package main\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n"
	if err := os.WriteFile(mainPath, []byte(source), 0644); err != nil {
		t.Fatal(err)
	}

	findings := (LintRule{RepositoryRoot: repoDir}).Check("")

	for _, finding := range findings {
		if finding.Rule == "repository-lint" &&
			finding.File == "main.go" &&
			finding.Line == 4 {
			return
		}
	}

	t.Fatalf("go vet file/line finding not found: %+v", findings)
}

func TestLintRuleExclusionsFilterUnformattedFile(t *testing.T) {
	repoDir := setupLintTestRepo(t)

	// Unformatted file in vendor/
	vendorDir := filepath.Join(repoDir, "vendor")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(vendorDir, "dep.go"),
		[]byte("package dep\nfunc Foo(){}\n"),
		0644,
	); err != nil {
		t.Fatal(err)
	}

	cfg := &LintConfig{
		Exclusions: []string{"vendor/**"},
	}
	findings := (LintRule{RepositoryRoot: repoDir, Config: cfg}).Check("")
	if len(findings) != 0 {
		t.Fatalf("expected exclusions to suppress vendor findings, got: %+v", findings)
	}
}

func TestLintRuleExclusionsFilterGoVet(t *testing.T) {
	repoDir := setupLintTestRepo(t)

	mainPath := filepath.Join(repoDir, "main.go")
	source := "package main\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n"
	if err := os.WriteFile(mainPath, []byte(source), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &LintConfig{
		Exclusions: []string{"main.go"},
	}
	findings := (LintRule{RepositoryRoot: repoDir, Config: cfg}).Check("")
	if len(findings) != 0 {
		t.Fatalf("expected main.go exclusion to suppress vet finding, got: %+v", findings)
	}
}

func TestLintRuleReportsUnavailableConfiguredAnalyzer(t *testing.T) {
	repoDir := setupLintTestRepo(t)

	cfg := &LintConfig{
		Analyzers: []string{"nonexistent-analyzer-xyz"},
	}
	findings := (LintRule{RepositoryRoot: repoDir, Config: cfg}).Check("")
	if len(findings) == 0 {
		t.Fatal("expected finding for unavailable configured analyzer, got 0")
	}

	found := false
	for _, f := range findings {
		if f.Rule == "repository-lint" && f.Severity == "high" && strings.Contains(f.Message, "nonexistent-analyzer-xyz is unavailable") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected unavailable tool finding, got: %+v", findings)
	}
}

func TestLintRuleConfigLoadedFromRepoConfigFile(t *testing.T) {
	repoDir := setupLintTestRepo(t)

	// Create .m3tal-review-config.json with exclusion
	cfgJSON := `{"lint": {"exclusions": ["main.go"]}}`
	if err := os.WriteFile(filepath.Join(repoDir, ".m3tal-review-config.json"), []byte(cfgJSON), 0644); err != nil {
		t.Fatal(err)
	}

	mainPath := filepath.Join(repoDir, "main.go")
	if err := os.WriteFile(mainPath, []byte("package main\nfunc main(){}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Without explicit config passed, LintRule reads .m3tal-review-config.json
	findings := (LintRule{RepositoryRoot: repoDir}).Check("")
	if len(findings) != 0 {
		t.Fatalf("expected .m3tal-review-config.json exclusion to suppress unformatted main.go, got: %+v", findings)
	}
}
