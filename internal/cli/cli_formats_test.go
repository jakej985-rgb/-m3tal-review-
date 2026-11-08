package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func captureStdout(fn func() error) (string, error) {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdout = w

	errChan := make(chan error, 1)
	go func() {
		errChan <- fn()
		w.Close()
	}()

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	r.Close()
	os.Stdout = origStdout
	execErr := <-errChan
	return buf.String(), execErr
}

func setupTestGitRepoWithFinding(t *testing.T) string {
	t.Helper()
	repoDir := t.TempDir()

	runGit := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	runGit("init")
	runGit("config", "user.name", "Test User")
	runGit("config", "user.email", "test@example.com")

	// Commit initial file
	if err := os.WriteFile(filepath.Join(repoDir, "auth.go"), []byte("package auth\n\nfunc login() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "auth.go")
	runGit("commit", "-m", "initial commit")

	// Stage a change containing a hardcoded credential finding
	changeContent := `package auth

func login() {
	password := "supersecret12345"
	_ = password
}
`
	if err := os.WriteFile(filepath.Join(repoDir, "auth.go"), []byte(changeContent), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "auth.go")

	return repoDir
}

func TestCLIReviewJSONL(t *testing.T) {
	repoDir := setupTestGitRepoWithFinding(t)

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	out, reviewErr := captureStdout(func() error {
		return executeWithArgs("review", []string{"--format", "jsonl"})
	})
	if reviewErr == nil {
		t.Fatalf("expected review to fail on finding, got nil")
	}

	// Output should contain at least one valid JSONL line
	scanner := bufio.NewScanner(strings.NewReader(out))
	foundJSONL := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			var obj map[string]interface{}
			if err := json.Unmarshal([]byte(line), &obj); err == nil {
				foundJSONL = true
				if obj["rule"] != "hardcoded-credential" {
					t.Errorf("expected rule hardcoded-credential, got %v", obj["rule"])
				}
				if obj["file"] != "auth.go" {
					t.Errorf("expected file auth.go, got %v", obj["file"])
				}
				if snip, ok := obj["snippet"].(string); !ok || !strings.Contains(snip, "supersecret12345") {
					t.Errorf("expected snippet to contain secret, got %v", obj["snippet"])
				}
			}
		}
	}
	if !foundJSONL {
		t.Fatalf("did not find valid JSONL record in review output:\n%s", out)
	}
}

func TestCLIReviewHTML(t *testing.T) {
	repoDir := setupTestGitRepoWithFinding(t)

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	out, reviewErr := captureStdout(func() error {
		return executeWithArgs("review", []string{"--format", "html"})
	})
	if reviewErr == nil {
		t.Fatalf("expected review to fail on finding, got nil")
	}

	if !strings.Contains(out, "<!DOCTYPE html>") {
		t.Errorf("expected HTML doctype in output")
	}
	if !strings.Contains(out, "<style>") {
		t.Errorf("expected embedded styles")
	}
	if !strings.Contains(out, "<script>") {
		t.Errorf("expected embedded script")
	}
	if !strings.Contains(out, `id="search-box"`) {
		t.Errorf("expected search-box in HTML")
	}
	if !strings.Contains(out, `id="filter-severity"`) {
		t.Errorf("expected filter-severity in HTML")
	}
	if !strings.Contains(out, `id="filter-rule"`) {
		t.Errorf("expected filter-rule in HTML")
	}
	if !strings.Contains(out, `id="filter-file"`) {
		t.Errorf("expected filter-file in HTML")
	}
	if !strings.Contains(out, `class="finding-card"`) {
		t.Errorf("expected finding-card in HTML")
	}
	if !strings.Contains(out, "hardcoded-credential") {
		t.Errorf("expected rule in HTML")
	}
}

func TestCLIReviewSnippetsFlag(t *testing.T) {
	repoDir := setupTestGitRepoWithFinding(t)

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	out, reviewErr := captureStdout(func() error {
		return executeWithArgs("review", []string{"--snippets"})
	})
	if reviewErr == nil {
		t.Fatalf("expected review to fail on finding, got nil")
	}

	if !strings.Contains(out, "[high] auth.go:4") {
		t.Errorf("expected finding header, got:\n%s", out)
	}
	if !strings.Contains(out, ">") || !strings.Contains(out, "+") {
		t.Errorf("expected snippet with diff markers in output, got:\n%s", out)
	}
}

func TestCLIAuditJSONLAndHTML(t *testing.T) {
	repoDir := setupTestGitRepoWithFinding(t)

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	// Test audit with jsonl
	outJSONL, auditErr := captureStdout(func() error {
		return executeWithArgs("audit", []string{"--format", "jsonl"})
	})
	if auditErr == nil {
		t.Fatalf("expected audit to fail on finding")
	}
	if !strings.Contains(outJSONL, `"rule":"hardcoded-credential"`) {
		t.Errorf("expected JSONL rule in audit output:\n%s", outJSONL)
	}

	// Test audit with html
	outHTML, auditErr2 := captureStdout(func() error {
		return executeWithArgs("audit", []string{"--format", "html"})
	})
	if auditErr2 == nil {
		t.Fatalf("expected audit to fail on finding")
	}
	if !strings.Contains(outHTML, "<!DOCTYPE html>") || !strings.Contains(outHTML, `id="search-box"`) {
		t.Errorf("expected HTML in audit output:\n%s", outHTML)
	}
}

func TestCLIHistoryShowFormats(t *testing.T) {
	repoDir := setupTestGitRepoWithFinding(t)

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	// Run review to produce a stored report
	_, _ = captureStdout(func() error {
		return executeWithArgs("review", nil)
	})

	reportsDir := filepath.Join(repoDir, ".m3tal-review", "reports")
	entries, err := os.ReadDir(reportsDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("expected stored reports in %s, err=%v", reportsDir, err)
	}
	runID := strings.TrimSuffix(entries[0].Name(), ".json")

	// 1. Test history show --format jsonl
	outJSONL, err := captureStdout(func() error {
		return executeWithArgs("history", []string{"show", runID, "--format", "jsonl"})
	})
	if err != nil {
		t.Fatalf("history show jsonl failed: %v", err)
	}
	if !strings.Contains(outJSONL, `"rule":"hardcoded-credential"`) {
		t.Errorf("expected JSONL rule in history show output:\n%s", outJSONL)
	}

	// 2. Test history show --format html
	outHTML, err := captureStdout(func() error {
		return executeWithArgs("history", []string{"show", runID, "--format", "html"})
	})
	if err != nil {
		t.Fatalf("history show html failed: %v", err)
	}
	if !strings.Contains(outHTML, "<!DOCTYPE html>") || !strings.Contains(outHTML, `id="search-box"`) {
		t.Errorf("expected HTML structure in history show output:\n%s", outHTML)
	}
}
