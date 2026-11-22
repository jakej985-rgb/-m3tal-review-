package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePRReviewOptions(t *testing.T) {
	args := []string{
		"--base", "origin/main",
		"--pr", "42",
		"--repo", "myorg/myrepo",
		"--interactive",
		"--post-gh",
		"--comment-only",
		"--output", "report.md",
		"--handle-comment", "@m3tal-review explain pipe-to-shell",
	}

	opts, err := parsePRReviewOptions(args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts.Base != "origin/main" {
		t.Errorf("expected origin/main, got %s", opts.Base)
	}
	if opts.PRNumber != 42 {
		t.Errorf("expected 42, got %d", opts.PRNumber)
	}
	if opts.Repo != "myorg/myrepo" {
		t.Errorf("expected myorg/myrepo, got %s", opts.Repo)
	}
	if !opts.Interactive {
		t.Errorf("expected Interactive to be true")
	}
	if !opts.PostGH {
		t.Errorf("expected PostGH to be true")
	}
	if !opts.CommentOnly {
		t.Errorf("expected CommentOnly to be true")
	}
	if opts.OutputFile != "report.md" {
		t.Errorf("expected report.md, got %s", opts.OutputFile)
	}
	if opts.HandleComment != "@m3tal-review explain pipe-to-shell" {
		t.Errorf("expected handle-comment body, got %s", opts.HandleComment)
	}
}

func TestInstallWorkflowCmd(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "m3tal-workflow-test-*")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize real git repo
	cmd := exec.Command("git", "init", tempDir)
	if err := cmd.Run(); err != nil {
		t.Fatalf("git init: %v", err)
	}

	origWd, _ := os.Getwd()
	_ = os.Chdir(tempDir)
	defer os.Chdir(origWd)

	// Run install workflow
	if err := runInstallWorkflow([]string{}); err != nil {
		t.Fatalf("runInstallWorkflow failed: %v", err)
	}

	workflowPath := filepath.Join(tempDir, ".github", "workflows", "m3tal-review.yml")
	content, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("read workflow file: %v", err)
	}

	if !strings.Contains(string(content), "Pure-Code AI-Like Review") {
		t.Errorf("expected workflow content to contain Pure-Code AI-Like Review")
	}
	if !strings.Contains(string(content), "m3tal-review pr-review") {
		t.Errorf("expected workflow content to call m3tal-review pr-review")
	}

	// Test idempotency / force flag
	if err := runInstallWorkflow([]string{}); err == nil {
		t.Errorf("expected error when overwriting without --force")
	}
	if err := runInstallWorkflow([]string{"--force"}); err != nil {
		t.Errorf("expected success with --force: %v", err)
	}
}
