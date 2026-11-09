package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func setupTestGitRepo(t *testing.T) string {
	t.Helper()
	repoDir := t.TempDir()

	initCmd := exec.Command("git", "init", repoDir)
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}

	mainFile := filepath.Join(repoDir, "main.go")
	if err := os.WriteFile(mainFile, []byte("package main\n\nfunc main() {}\n"), 0644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}

	addCmd := exec.Command("git", "-C", repoDir, "add", "main.go")
	if out, err := addCmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}

	commitCmd := exec.Command(
		"git", "-C", repoDir,
		"-c", "user.name=Test",
		"-c", "user.email=test@example.com",
		"commit", "-m", "init",
	)
	if out, err := commitCmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}

	return repoDir
}

func TestRunPipelineReviewScope(t *testing.T) {
	repoDir := setupTestGitRepo(t)
	runID, err := review.NewRunID()
	if err != nil {
		t.Fatalf("NewRunID: %v", err)
	}

	diff := "diff --git a/main.go b/main.go\n--- a/main.go\n+++ b/main.go\n@@ -1,3 +1,4 @@\n package main\n+// comment\n func main() {}\n"
	finding := review.Finding{
		Rule:     "test-rule",
		Severity: "info",
		File:     "main.go",
		Line:     2,
		Message:  "informational test note",
	}

	cfg := RunnerConfig{
		Scope:           "staged",
		RepositoryRoot:  repoDir,
		Branch:          "master",
		RunID:           runID,
		Profile:         "fast",
		Format:          "text",
		Version:         "v0.1.0-test",
		Diff:            diff,
		StagedFiles:     []string{"main.go"},
		InitialFindings: []review.Finding{finding},
	}

	err = RunPipeline(cfg)
	if err != nil {
		t.Fatalf("RunPipeline staged: unexpected error: %v", err)
	}

	reportPath := filepath.Join(repoDir, ".m3tal-review", "reports", runID+".json")
	report, err := review.ReadReport(reportPath)
	if err != nil {
		t.Fatalf("ReadReport: %v", err)
	}

	if report.Scope != "staged" {
		t.Errorf("expected scope staged, got %s", report.Scope)
	}
	if report.RunID != runID {
		t.Errorf("expected runID %s, got %s", runID, report.RunID)
	}
	if len(report.ReviewedFiles) != 1 || report.ReviewedFiles[0] != "main.go" {
		t.Errorf("unexpected report files: %v", report.ReviewedFiles)
	}
	if report.Attestation == nil {
		t.Error("expected attestation to be generated")
	}

	historyPath := filepath.Join(repoDir, ".m3tal-review", "history.jsonl")
	history, err := review.ReadHistory(historyPath)
	if err != nil {
		t.Fatalf("ReadHistory: %v", err)
	}
	if len(history) != 1 || history[0].RunID != runID {
		t.Errorf("unexpected history: %v", history)
	}
}

func TestRunPipelineAuditScope(t *testing.T) {
	repoDir := setupTestGitRepo(t)
	runID, err := review.NewRunID()
	if err != nil {
		t.Fatalf("NewRunID: %v", err)
	}

	finding := review.Finding{
		Rule:     "audit-rule",
		Severity: "info",
		File:     "main.go",
		Line:     1,
		Message:  "audit info signal",
	}

	cfg := RunnerConfig{
		Scope:           "working-tree",
		RepositoryRoot:  repoDir,
		Branch:          "master",
		RunID:           runID,
		Profile:         "fast",
		Format:          "json",
		Version:         "v0.1.0-test",
		ReviewedFiles:   []string{"main.go"},
		InitialFindings: []review.Finding{finding},
		SnapshotHash:    "deadbeefcafebabe",
		MaxFiles:        100,
		MaxBytes:        1024,
	}

	err = RunPipeline(cfg)
	if err != nil {
		t.Fatalf("RunPipeline audit: unexpected error: %v", err)
	}

	reportPath := filepath.Join(repoDir, ".m3tal-review", "reports", runID+".json")
	report, err := review.ReadReport(reportPath)
	if err != nil {
		t.Fatalf("ReadReport: %v", err)
	}

	if report.Scope != "working-tree" {
		t.Errorf("expected scope working-tree, got %s", report.Scope)
	}
	if report.DiffHash != "deadbeefcafebabe" {
		t.Errorf("expected snapshot hash deadbeefcafebabe, got %s", report.DiffHash)
	}

	// Verify low finding fails audit
	cfgFail := cfg
	cfgFail.RunID, _ = review.NewRunID()
	cfgFail.InitialFindings = []review.Finding{{
		Rule:     "audit-rule",
		Severity: "low",
		File:     "main.go",
		Line:     1,
		Message:  "audit low signal",
	}}
	err = RunPipeline(cfgFail)
	if err == nil || !strings.Contains(err.Error(), "audit found 1 issue(s)") {
		t.Fatalf("expected audit failure error, got: %v", err)
	}
}

func TestRunPipelineFailOnThreshold(t *testing.T) {
	repoDir := setupTestGitRepo(t)
	runID, _ := review.NewRunID()

	highFinding := review.Finding{
		Rule:     "sec-high",
		Severity: "high",
		File:     "main.go",
		Line:     1,
		Message:  "high severity issue",
	}

	baseCfg := RunnerConfig{
		Scope:           "staged",
		RepositoryRoot:  repoDir,
		Branch:          "master",
		RunID:           runID,
		Profile:         "fast",
		Format:          "text",
		Version:         "test",
		StagedFiles:     []string{"main.go"},
		InitialFindings: []review.Finding{highFinding},
	}

	// FailOn "critical" -> should pass because issue is high (< critical)
	cfgCritical := baseCfg
	cfgCritical.FailOn = "critical"
	if err := RunPipeline(cfgCritical); err != nil {
		t.Errorf("expected pass with FailOn critical, got: %v", err)
	}

	// FailOn "high" -> should fail because issue is high (>= high)
	cfgHigh := baseCfg
	cfgHigh.RunID, _ = review.NewRunID()
	cfgHigh.FailOn = "high"
	err := RunPipeline(cfgHigh)
	if err == nil {
		t.Errorf("expected error with FailOn high, got nil")
	} else if !strings.Contains(err.Error(), "found 1 issue(s) at or above high") {
		t.Errorf("unexpected error text: %v", err)
	}
}

func TestRunPipelineUnanalyzedFilesReporting(t *testing.T) {
	repoDir := setupTestGitRepo(t)

	// In working-tree scope
	auditCfg := RunnerConfig{
		Scope:           "working-tree",
		RepositoryRoot:  repoDir,
		Branch:          "master",
		RunID:           "audit-unanal",
		Profile:         "fast",
		Format:          "text",
		Version:         "test",
		ReviewedFiles:   []string{"main.go"},
		UnanalyzedFiles: []string{"binary.bin"},
	}

	err := RunPipeline(auditCfg)
	if err == nil {
		t.Fatalf("expected audit error for unanalyzed file, got nil")
	}
	if !strings.Contains(err.Error(), "audit incomplete: 1 file(s) could not be analyzed") {
		t.Errorf("unexpected audit error: %v", err)
	}

	// In staged scope
	reviewCfg := RunnerConfig{
		Scope:           "staged",
		RepositoryRoot:  repoDir,
		Branch:          "master",
		RunID:           "review-unanal",
		Profile:         "fast",
		Format:          "text",
		Version:         "test",
		StagedFiles:     []string{"main.go"},
		UnanalyzedFiles: []string{"submodule"},
	}

	err = RunPipeline(reviewCfg)
	if err == nil {
		t.Fatalf("expected review error for unanalyzed file, got nil")
	}
	if !strings.Contains(err.Error(), "review incomplete: 1 staged file(s) could not be analyzed") {
		t.Errorf("unexpected review error: %v", err)
	}
}
