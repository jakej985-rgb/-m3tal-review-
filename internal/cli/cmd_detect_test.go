package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectionAndPlanningCLICommands(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := runScanCommand([]string{root, "--format", "json"}); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if err := runDetectCommand([]string{root, "--format", "json"}); err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if err := runLanguagesCommand([]string{"--format", "json"}); err != nil {
		t.Fatalf("languages failed: %v", err)
	}
	if err := runAnalyzersCommand([]string{"--language", "go", "--format", "json"}); err != nil {
		t.Fatalf("analyzers failed: %v", err)
	}
	if err := runExplainCommand([]string{root, "--profile", "security", "--format", "json"}); err != nil {
		t.Fatalf("explain failed: %v", err)
	}
	if err := runMultiLangCheckCommand([]string{root, "--profile", "security", "--format", "json"}); err != nil {
		t.Fatalf("check failed: %v", err)
	}
}
