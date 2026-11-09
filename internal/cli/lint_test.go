package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLintConfigExclusionsFromConfigFile(t *testing.T) {
	repoDir := setupLintRepo(t, `package main
func main(){println("unformatted")}
`)

	// Initially, lint fails due to unformatted main.go
	_, err := captureLintOutput(t)
	if err == nil {
		t.Fatal("expected lint to fail on unformatted file")
	}

	// Add .m3tal-review-config.json with exclusion for main.go
	cfgJSON := `{"lint": {"exclusions": ["main.go"]}}`
	if err := os.WriteFile(filepath.Join(repoDir, ".m3tal-review-config.json"), []byte(cfgJSON), 0644); err != nil {
		t.Fatal(err)
	}

	output, err := captureLintOutput(t)
	if err != nil {
		t.Fatalf("expected lint to pass with exclusion in config file, got err: %v\noutput: %s", err, output)
	}
	if !strings.Contains(output, "Formatting passed.") {
		t.Errorf("output missing formatting pass:\n%s", output)
	}
}

func TestLintConfigExclusionsFromPolicyFile(t *testing.T) {
	repoDir := setupLintRepo(t, `package main
func main(){println("unformatted")}
`)

	// Add .m3tal-review-policy.json with lint exclusions
	policyJSON := `{"lint": {"exclusions": ["main.go"]}}`
	if err := os.WriteFile(filepath.Join(repoDir, ".m3tal-review-policy.json"), []byte(policyJSON), 0644); err != nil {
		t.Fatal(err)
	}

	output, err := captureLintOutput(t)
	if err != nil {
		t.Fatalf("expected lint to pass with exclusion in policy file, got err: %v\noutput: %s", err, output)
	}
	if !strings.Contains(output, "Formatting passed.") {
		t.Errorf("output missing formatting pass:\n%s", output)
	}
}

func TestLintReportsUnavailableConfiguredAnalyzer(t *testing.T) {
	repoDir := setupLintRepo(t, `package main

func main() {
	println("hello")
}
`)

	// Configure an unavailable analyzer in .m3tal-review-config.json
	cfgJSON := `{"lint": {"analyzers": ["custom-unavailable-linter"]}}`
	if err := os.WriteFile(filepath.Join(repoDir, ".m3tal-review-config.json"), []byte(cfgJSON), 0644); err != nil {
		t.Fatal(err)
	}

	output, err := captureLintOutput(t)
	if err == nil {
		t.Fatal("expected lint to fail when configured analyzer is unavailable")
	}
	if !strings.Contains(err.Error(), "custom-unavailable-linter is unavailable") {
		t.Fatalf("expected error message to mention unavailable tool, got: %v\noutput: %s", err, output)
	}
}

func TestLintCLIFlagExclusions(t *testing.T) {
	setupLintRepo(t, `package main
func main(){println("unformatted")}
`)

	// Run lint with --exclude main.go
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = writer

	runErr := executeWithArgs("lint", []string{"--exclude=main.go"})

	os.Stdout = origStdout
	_ = writer.Close()
	_ = reader.Close()

	if runErr != nil {
		t.Fatalf("expected --exclude flag to pass, got err: %v", runErr)
	}
}
