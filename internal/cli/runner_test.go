package cli

import (
	"crypto/sha256"
	"encoding/hex"
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

func writeMarkerPlugin(t *testing.T, dir, name, markerPath string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir plugin dir: %v", err)
	}
	script := "#!/bin/sh\ntouch \"" + markerPath + "\"\necho '{\"name\":\"" + name + "\",\"version\":\"1.0.0\"}'\n"
	path := filepath.Join(dir, "m3tal-review-plugin-"+name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write plugin: %v", err)
	}
}

func TestRunPipelineDoesNotLoadRepoPluginsByDefault(t *testing.T) {
	repoDir := setupTestGitRepo(t)
	runID, err := review.NewRunID()
	if err != nil {
		t.Fatalf("NewRunID: %v", err)
	}

	marker := filepath.Join(repoDir, "repo-plugin-ran.marker")
	writeMarkerPlugin(t, filepath.Join(repoDir, ".m3tal-review", "plugins"), "evil", marker)

	cfg := RunnerConfig{
		Scope:           "staged",
		RepositoryRoot:  repoDir,
		Branch:          "master",
		RunID:           runID,
		Profile:         "fast",
		Format:          "text",
		Version:         "test",
		Diff:            "diff --git a/main.go b/main.go\n--- a/main.go\n+++ b/main.go\n@@ -1,3 +1,4 @@\n package main\n+// comment\n func main() {}\n",
		StagedFiles:     []string{"main.go"},
		InitialFindings: nil,
	}

	if err := RunPipeline(cfg); err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("repository plugin executed without opt-in; marker exists (stat err=%v)", err)
	}
}

func TestRunPipelineRepoPluginsRequireOptIn(t *testing.T) {
	repoDir := setupTestGitRepo(t)

	marker := filepath.Join(repoDir, "repo-plugin-ran.marker")
	writeMarkerPlugin(t, filepath.Join(repoDir, ".m3tal-review", "plugins"), "evil", marker)

	newCfg := func() RunnerConfig {
		runID, _ := review.NewRunID()
		return RunnerConfig{
			Scope:           "staged",
			RepositoryRoot:  repoDir,
			Branch:          "master",
			RunID:           runID,
			Profile:         "fast",
			Format:          "text",
			Version:         "test",
			Diff:            "diff --git a/main.go b/main.go\n--- a/main.go\n+++ b/main.go\n@@ -1,3 +1,4 @@\n package main\n+// comment\n func main() {}\n",
			StagedFiles:     []string{"main.go"},
			InitialFindings: nil,
		}
	}

	// Explicit --plugin-dir outside the repo loads plugins without opt-in.
	trustedDir := t.TempDir()
	trustedMarker := filepath.Join(trustedDir, "trusted-ran.marker")
	writeMarkerPlugin(t, trustedDir, "trusted", trustedMarker)

	cfg := newCfg()
	cfg.PluginDir = trustedDir
	if err := RunPipeline(cfg); err != nil {
		t.Fatalf("RunPipeline trusted dir: %v", err)
	}
	if _, err := os.Stat(trustedMarker); err != nil {
		t.Fatalf("expected trusted plugin to run, marker missing: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("repo plugin ran alongside trusted plugin without opt-in")
	}

	// --allow-repo-plugins alone is not enough: repository plugin executables
	// must also have their SHA-256 on the user's allowlist (fail closed).
	cfg2 := newCfg()
	cfg2.AllowRepoPlugins = true
	cfg2.PluginDir = ""
	if err := RunPipeline(cfg2); err != nil {
		t.Fatalf("RunPipeline allow repo plugins: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("repo plugin ran with opt-in but no hash allowlist")
	}

	// With the executable's SHA-256 allowlisted, the repo plugin runs.
	pluginPath := filepath.Join(repoDir, ".m3tal-review", "plugins", "m3tal-review-plugin-evil")
	pluginBytes, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatalf("read plugin: %v", err)
	}
	sum := sha256.Sum256(pluginBytes)
	cfg3 := newCfg()
	cfg3.AllowRepoPlugins = true
	cfg3.RepoPluginAllowSHA256 = []string{hex.EncodeToString(sum[:])}
	if err := RunPipeline(cfg3); err != nil {
		t.Fatalf("RunPipeline allowlisted repo plugin: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("expected allowlisted repo plugin to run, marker missing: %v", err)
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
