package repair

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// initGitRepo initializes a local git repository in dir with an initial commit.
func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	runCmd(t, dir, "git", "init")
	runCmd(t, dir, "git", "config", "user.name", "Tester")
	runCmd(t, dir, "git", "config", "user.email", "tester@example.com")
	_ = os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".m3tal-review/\n"), 0644)
	runCmd(t, dir, "git", "add", "-A")
	runCmd(t, dir, "git", "commit", "-m", "initial commit", "--no-gpg-sign")
}

func runCmd(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\nOutput: %s", name, strings.Join(args, " "), err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func TestRepairWorkflowApprovedAndAppliedWithoutCommitOrPush(t *testing.T) {
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)

	// Create vulnerable code file
	vulnFile := "storage.go"
	vulnContent := "package main\nimport \"os\"\nfunc Write() {\n\tos.WriteFile(\"data.bin\", []byte(\"hi\"), 0777)\n}\n"
	if err := os.WriteFile(filepath.Join(repoDir, vulnFile), []byte(vulnContent), 0644); err != nil {
		t.Fatal(err)
	}

	finding := review.Finding{
		ID:       "find-perm-1",
		Rule:     "world-writable-file-mode",
		Severity: "high",
		File:     vulnFile,
		Line:     4,
		Message:  "File operation grants world-write permission",
	}

	rules := []review.Rule{
		review.PermissionsRule{RepositoryRoot: repoDir, WorkingTree: true},
	}

	engine := NewRepairEngine(repoDir, rules)
	engine.TestRunnerFactory = func(sandboxDir string) func() error {
		// Tests pass in sandbox
		return func() error { return nil }
	}

	approvalPrompted := false
	engine.ApprovalHandler = func(prop *Proposal, v review.RemediationVerificationResult) (bool, error) {
		approvalPrompted = true
		if v.Status != "fixed" {
			t.Errorf("expected verification status 'fixed', got %q", v.Status)
		}
		return true, nil // User approves
	}

	headBefore := runCmd(t, repoDir, "git", "rev-parse", "HEAD")

	res, err := engine.RepairFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("RepairFinding error: %v", err)
	}

	if !approvalPrompted {
		t.Fatal("expected approval handler to be called")
	}

	if res.Outcome != OutcomeApprovedAndApplied || !res.Applied {
		t.Fatalf("expected outcome %q and applied=true, got %q, applied=%t", OutcomeApprovedAndApplied, res.Outcome, res.Applied)
	}

	// Verify working tree file was updated
	updatedContent, err := os.ReadFile(filepath.Join(repoDir, vulnFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updatedContent), "0644") {
		t.Fatalf("expected 0644 in updated file, got: %s", string(updatedContent))
	}

	// CRITICAL CHECK: Verify git was NEVER auto-committed or pushed!
	headAfter := runCmd(t, repoDir, "git", "rev-parse", "HEAD")
	if headBefore != headAfter {
		t.Fatalf("FATAL: git commit was created! Before=%s, After=%s", headBefore, headAfter)
	}

	// Verify audit log
	auditEntries, err := ReadRepairAudit(engine.AuditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if len(auditEntries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(auditEntries))
	}
	if auditEntries[0].Outcome != OutcomeApprovedAndApplied || !auditEntries[0].Approved || !auditEntries[0].Applied {
		t.Errorf("audit entry mismatch: %+v", auditEntries[0])
	}
}

func TestRepairWorkflowRejectedLeavesWorkingTreeUntouched(t *testing.T) {
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)

	vulnFile := "storage.go"
	vulnContent := "package main\nimport \"os\"\nfunc Write() {\n\tos.WriteFile(\"data.bin\", []byte(\"hi\"), 0777)\n}\n"
	if err := os.WriteFile(filepath.Join(repoDir, vulnFile), []byte(vulnContent), 0644); err != nil {
		t.Fatal(err)
	}

	finding := review.Finding{
		ID:       "find-perm-2",
		Rule:     "world-writable-file-mode",
		Severity: "high",
		File:     vulnFile,
		Line:     4,
		Message:  "File operation grants world-write permission",
	}

	rules := []review.Rule{
		review.PermissionsRule{RepositoryRoot: repoDir, WorkingTree: true},
	}

	engine := NewRepairEngine(repoDir, rules)
	engine.ApprovalHandler = func(prop *Proposal, v review.RemediationVerificationResult) (bool, error) {
		return false, nil // User rejects
	}

	res, err := engine.RepairFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("RepairFinding error: %v", err)
	}

	if res.Outcome != OutcomeRejected || res.Applied {
		t.Fatalf("expected outcome %q and applied=false, got %q, applied=%t", OutcomeRejected, res.Outcome, res.Applied)
	}

	// Verify file is untouched
	currentContent, err := os.ReadFile(filepath.Join(repoDir, vulnFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(currentContent) != vulnContent {
		t.Fatalf("expected working tree to be untouched, but content changed: %s", string(currentContent))
	}
}

func TestRepairWorkflowPathTraversalRejection(t *testing.T) {
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)

	// Attempt path traversal targeting outside file
	finding := review.Finding{
		ID:       "traversal-1",
		Rule:     "world-writable-file-mode",
		Severity: "high",
		File:     "../../etc/passwd",
		Line:     1,
		Message:  "File operation grants world-write permission",
	}

	engine := NewRepairEngine(repoDir, nil)
	res, err := engine.RepairFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("expected error to be captured in result, got: %v", err)
	}

	if res.Outcome != OutcomeVerificationFailed && res.Outcome != OutcomeAttemptLimitExceeded {
		t.Fatalf("expected verification failure for path traversal, got %q", res.Outcome)
	}
	if res.Applied {
		t.Fatal("applied should be false for path traversal attack")
	}

	// Verify audit log records failure
	entries, _ := ReadRepairAudit(engine.AuditPath)
	if len(entries) == 0 {
		t.Fatal("expected audit log entry for traversal attempt")
	}
	if entries[0].Applied || entries[0].Approved {
		t.Fatal("traversal attempt must not be approved or applied in audit")
	}
}

func TestRepairWorkflowMalformedPatchRejection(t *testing.T) {
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)

	file := "main.go"
	_ = os.WriteFile(filepath.Join(repoDir, file), []byte("package main\n"), 0644)

	// Malformed patch validation test
	malformedPatch := `--- a/main.go
+++ b/main.go
@@ invalid @@
-foo
+bar
`
	err := ValidatePatchBoundaries(repoDir, file, malformedPatch)
	if err == nil {
		t.Fatal("expected malformed patch to fail boundary validation")
	}
	if !strings.Contains(err.Error(), "malformed hunk header") {
		t.Errorf("expected malformed hunk error, got: %v", err)
	}
}

func TestRepairWorkflowFailureCleanupOnTestRunnerRegression(t *testing.T) {
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)

	vulnFile := "clean.go"
	content := "func main() {   \n}\n"
	_ = os.WriteFile(filepath.Join(repoDir, vulnFile), []byte(content), 0644)

	finding := review.Finding{
		ID:       "f-white",
		Rule:     "code-slop",
		Severity: "low",
		File:     vulnFile,
		Message:  "Trailing whitespace detected",
	}

	engine := NewRepairEngine(repoDir, nil)
	// Injected failing test runner simulating regression
	engine.TestRunnerFactory = func(sandboxDir string) func() error {
		return func() error {
			return fmt.Errorf("regression test suite failed: assertion error in math_test.go")
		}
	}

	res, err := engine.RepairFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}

	if res.Outcome != OutcomeVerificationFailed && res.Outcome != OutcomeAttemptLimitExceeded {
		t.Fatalf("expected verification failure due to test regression, got outcome %q", res.Outcome)
	}
	if res.Applied {
		t.Fatal("proposal should not be applied when regression tests fail")
	}

	// Working tree must remain untouched
	current, _ := os.ReadFile(filepath.Join(repoDir, vulnFile))
	if string(current) != content {
		t.Fatalf("working tree modified despite failure! Got: %q", string(current))
	}
}

func TestRepairWorkflowBoundedAttemptsAndRepeatedAttempts(t *testing.T) {
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)

	file := "eval.go"
	content := "package main\nfunc test() {\n\tif x == true {\n\t}\n}\n"
	_ = os.WriteFile(filepath.Join(repoDir, file), []byte(content), 0644)

	finding := review.Finding{
		ID:       "f-repeat",
		Rule:     "code-slop",
		Severity: "low",
		File:     file,
		Line:     3,
		Message:  "Redundant boolean comparison",
	}

	engine := NewRepairEngine(repoDir, nil)
	engine.MaxAttempts = 3
	attemptsCounted := 0

	// Simulating test runner that always fails, forcing attempts up to bound
	engine.TestRunnerFactory = func(sandboxDir string) func() error {
		return func() error {
			attemptsCounted++
			return fmt.Errorf("persistent build failure")
		}
	}

	res, err := engine.RepairFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}

	if res.Attempts != 3 {
		t.Fatalf("expected attempts to be strictly bounded to 3, got %d (callback called %d)", res.Attempts, attemptsCounted)
	}

	if res.Outcome != OutcomeAttemptLimitExceeded {
		t.Fatalf("expected outcome %q, got %q", OutcomeAttemptLimitExceeded, res.Outcome)
	}

	if res.Applied {
		t.Fatal("applied must be false when attempt limit exceeded")
	}

	// Audit entry should record 3 attempts and OutcomeAttemptLimitExceeded
	entries, _ := ReadRepairAudit(engine.AuditPath)
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(entries))
	}
	if entries[0].Attempts != 3 || entries[0].Outcome != OutcomeAttemptLimitExceeded {
		t.Errorf("audit entry attempt mismatch: %+v", entries[0])
	}
}

func TestRepairWorkflowDryRun(t *testing.T) {
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)

	file := "clean.go"
	content := "func test() {   \n}\n"
	_ = os.WriteFile(filepath.Join(repoDir, file), []byte(content), 0644)

	finding := review.Finding{
		ID:       "dry-1",
		Rule:     "code-slop",
		Severity: "low",
		File:     file,
		Message:  "Trailing whitespace detected",
	}

	engine := NewRepairEngine(repoDir, nil)
	engine.DryRun = true

	res, err := engine.RepairFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Outcome != OutcomeDryRun || res.Applied {
		t.Fatalf("expected outcome 'dry_run' and applied=false, got %q, applied=%t", res.Outcome, res.Applied)
	}

	// Working tree must remain untouched
	current, _ := os.ReadFile(filepath.Join(repoDir, file))
	if string(current) != content {
		t.Fatal("working tree modified in dry-run mode")
	}
}

func TestRepairWorkflowScopeRulesWorkingTree(t *testing.T) {
	rules := []review.Rule{
		review.PermissionsRule{RepositoryRoot: "/orig/repo", WorkingTree: false},
	}
	scoped := scopeRulesToDir(rules, "/sandbox/dir")
	if len(scoped) != 1 {
		t.Fatalf("expected 1 scoped rule, got %d", len(scoped))
	}
	pr, ok := scoped[0].(review.PermissionsRule)
	if !ok {
		t.Fatalf("expected PermissionsRule type, got %T", scoped[0])
	}
	if pr.RepositoryRoot != "/sandbox/dir" {
		t.Errorf("expected RepositoryRoot = /sandbox/dir, got %q", pr.RepositoryRoot)
	}
	if !pr.WorkingTree {
		t.Errorf("expected WorkingTree = true on scoped rule, got false")
	}
}

func TestRepairWorkflowMultiFindingIterativeAttempts(t *testing.T) {
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)

	file := "eval.go"
	// 2 separate redundant booleans in the same file
	content := "package main\nfunc test() {\n\tif x == true {\n\t\tprintln(\"1\")\n\t}\n\tif y == false {\n\t\tprintln(\"2\")\n\t}\n}\n"
	_ = os.WriteFile(filepath.Join(repoDir, file), []byte(content), 0644)

	finding := review.Finding{
		ID:       "f-iter-1",
		Rule:     "code-slop",
		Severity: "low",
		File:     file,
		Line:     3,
		Message:  "Redundant boolean comparison",
	}

	rules := []review.Rule{
		review.SlopRule{RepositoryRoot: repoDir},
	}

	engine := NewRepairEngine(repoDir, rules)
	engine.MaxAttempts = 3
	engine.ApprovalHandler = func(prop *Proposal, v review.RemediationVerificationResult) (bool, error) {
		return true, nil
	}

	res, err := engine.RepairFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}

	if res.Outcome != OutcomeApprovedAndApplied || !res.Applied {
		t.Fatalf("expected approved_and_applied, got %q", res.Outcome)
	}

	// Verify working tree file was updated
	updated, err := os.ReadFile(filepath.Join(repoDir, file))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(updated), "== true") {
		t.Fatalf("expected redundant boolean == true to be removed, got: %s", string(updated))
	}
}
