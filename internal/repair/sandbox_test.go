package repair

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestSandboxIsolationAndWorkingTreeUntouched(t *testing.T) {
	repoDir := t.TempDir()

	testFile := filepath.Join(repoDir, "test.txt")
	originalContent := "original content line\n"
	if err := os.WriteFile(testFile, []byte(originalContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create sandbox (copy mode)
	sb, err := NewSandbox(repoDir, false)
	if err != nil {
		t.Fatalf("failed to create sandbox: %v", err)
	}
	defer sb.Close()

	// Apply change inside sandbox
	prop := NewProposal(
		"p1",
		review.Finding{},
		"test-fixer",
		"test.txt",
		originalContent,
		"modified content inside sandbox\n",
		"test modification",
	)

	if err := sb.ApplyProposal(prop); err != nil {
		t.Fatalf("failed to apply proposal in sandbox: %v", err)
	}

	// Verify sandbox file was modified
	sandboxContent, err := os.ReadFile(filepath.Join(sb.TempDir, "test.txt"))
	if err != nil {
		t.Fatalf("read sandbox file: %v", err)
	}
	if string(sandboxContent) != "modified content inside sandbox\n" {
		t.Fatalf("sandbox file not modified as expected: got %q", string(sandboxContent))
	}

	// CRITICAL CHECK: Verify user's original working tree remains byte-for-byte untouched!
	userTreeContent, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("read user working tree file: %v", err)
	}
	if string(userTreeContent) != originalContent {
		t.Fatalf("FATAL: user's working tree was modified! Expected %q, got %q", originalContent, string(userTreeContent))
	}
}

func TestSandboxFailureCleanup(t *testing.T) {
	repoDir := t.TempDir()
	f := filepath.Join(repoDir, "foo.go")
	_ = os.WriteFile(f, []byte("package main\n"), 0644)

	sb, err := NewSandbox(repoDir, false)
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}

	tempDir := sb.TempDir
	if _, err := os.Stat(tempDir); os.IsNotExist(err) {
		t.Fatalf("expected sandbox directory %q to exist", tempDir)
	}

	// Close sandbox to simulate failure cleanup
	if err := sb.Close(); err != nil {
		t.Fatalf("sandbox.Close() returned error: %v", err)
	}

	// Verify sandbox temp directory was completely removed
	if _, err := os.Stat(tempDir); !os.IsNotExist(err) {
		t.Fatalf("expected sandbox directory %q to be removed upon Close(), but still exists", tempDir)
	}
}
