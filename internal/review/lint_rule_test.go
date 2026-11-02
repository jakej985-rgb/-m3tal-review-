package review

import (
	"os"
	"path/filepath"
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
