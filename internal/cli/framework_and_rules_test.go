package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestParseFrameworkAndRulesFlags(t *testing.T) {
	// 1. Review options
	opts, err := parseReviewOptions([]string{"--framework", "gin,echo", "--rules", "custom.yaml"})
	if err != nil {
		t.Fatalf("parseReviewOptions failed: %v", err)
	}
	if len(opts.Framework) != 2 || opts.Framework[0] != "gin" || opts.Framework[1] != "echo" {
		t.Errorf("unexpected framework options: %v", opts.Framework)
	}
	if opts.RulesFile != "custom.yaml" {
		t.Errorf("expected RulesFile 'custom.yaml', got %q", opts.RulesFile)
	}

	// 2. Audit options
	auditOpts, err := parseAuditOptions([]string{"--framework", "fiber", "--rules", "my-rules.json"})
	if err != nil {
		t.Fatalf("parseAuditOptions failed: %v", err)
	}
	if len(auditOpts.Framework) != 1 || auditOpts.Framework[0] != "fiber" {
		t.Errorf("unexpected audit framework options: %v", auditOpts.Framework)
	}
	if auditOpts.RulesFile != "my-rules.json" {
		t.Errorf("expected audit RulesFile 'my-rules.json', got %q", auditOpts.RulesFile)
	}
}

func TestReviewWithFrameworkPacks(t *testing.T) {
	repoDir := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, output)
		}
	}

	runGit("init")
	runGit("config", "user.name", "Test User")
	runGit("config", "user.email", "test@example.com")

	// Commit initial file
	if err := os.WriteFile(filepath.Join(repoDir, "go.mod"), []byte("module testapp\ngo 1.23\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "go.mod")
	runGit("commit", "-m", "init")

	// Stage a file containing a Gin bug
	ginHandler := `package main

import "github.com/gin-gonic/gin"

func handle(c *gin.Context) {
	var req struct{ Name string }
	_ = c.BindJSON(&req)
}
`
	if err := os.WriteFile(filepath.Join(repoDir, "handler.go"), []byte(ginHandler), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "handler.go")

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	// Run review with explicit --framework gin
	output, reviewErr := captureOutput(func() error {
		return executeWithArgs("review", []string{"--framework", "gin"})
	})

	if reviewErr == nil {
		t.Fatalf("expected review failure due to finding, got nil")
	}

	// Verify framework finding is reported in output
	if !strings.Contains(output, "gin-unhandled-binding") {
		t.Errorf("expected 'gin-unhandled-binding' in output, got: %s", output)
	}

	// Verify framework check metadata is printed
	if !strings.Contains(output, "Check [passed] framework:gin: Gin framework pack v1.0.0 executed") {
		t.Errorf("expected framework:gin check in output, got: %s", output)
	}

	// Read saved report to inspect CheckResult structure directly
	reportsDir := filepath.Join(repoDir, ".m3tal-review", "reports")
	entries, err := os.ReadDir(reportsDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("failed to read report file: %v", err)
	}
	reportData, err := os.ReadFile(filepath.Join(reportsDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}
	var report review.Report
	if err := json.Unmarshal(reportData, &report); err != nil {
		t.Fatalf("failed to parse report: %v", err)
	}

	foundCheck := false
	for _, c := range report.Checks {
		if c.Name == "framework:gin" {
			foundCheck = true
			if c.Category != "framework" {
				t.Errorf("expected category 'framework', got %q", c.Category)
			}
			if c.Status != "passed" {
				t.Errorf("expected status 'passed', got %q", c.Status)
			}
			if c.Version != "1.0.0" {
				t.Errorf("expected version '1.0.0', got %q", c.Version)
			}
			break
		}
	}
	if !foundCheck {
		t.Errorf("expected check 'framework:gin' in report.Checks, got: %+v", report.Checks)
	}
}

func TestReviewAutoDetectsFrameworkFromGoMod(t *testing.T) {
	repoDir := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, output)
		}
	}

	runGit("init")
	runGit("config", "user.name", "Test User")
	runGit("config", "user.email", "test@example.com")

	goMod := `module testapp
go 1.23
require github.com/gin-gonic/gin v1.9.1
`
	if err := os.WriteFile(filepath.Join(repoDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "go.mod")
	runGit("commit", "-m", "init")

	// Stage a clean file so review runs
	if err := os.WriteFile(filepath.Join(repoDir, "clean.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "clean.go")

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	output, reviewErr := captureOutput(func() error {
		return executeWithArgs("review", []string{})
	})
	if reviewErr != nil {
		t.Fatalf("unexpected review error: %v, output: %s", reviewErr, output)
	}

	if !strings.Contains(output, "Check [passed] framework:gin") {
		t.Errorf("expected auto-detected check 'framework:gin' in output, got: %s", output)
	}
}

func TestReviewWithCustomRules(t *testing.T) {
	repoDir := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, output)
		}
	}

	runGit("init")
	runGit("config", "user.name", "Test User")
	runGit("config", "user.email", "test@example.com")

	// Commit custom rules file into repo
	customRules := `version: "1.0"
rules:
  - id: custom-no-raw-sql
    name: "Raw SQL disallow"
    severity: high
    category: security
    message: "String concatenation in SQL queries"
    languages: ["go"]
    pattern: 'db\.Query\s*\([^)]*\+'
    remediation: "Use parameterized queries"
`
	rulesPath := filepath.Join(repoDir, ".m3tal-review-rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(customRules), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", ".m3tal-review-rules.yaml")
	runGit("commit", "-m", "init")

	// Stage code triggering custom rule
	code := `package main

import "database/sql"

func queryUser(db *sql.DB, id string) {
	db.Query("SELECT * FROM users WHERE id = " + id)
}
`
	if err := os.WriteFile(filepath.Join(repoDir, "db.go"), []byte(code), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "db.go")

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	output, reviewErr := captureOutput(func() error {
		return executeWithArgs("review", []string{})
	})

	if reviewErr == nil {
		t.Fatalf("expected review error on custom finding, got nil")
	}

	if !strings.Contains(output, "custom-no-raw-sql") {
		t.Errorf("expected finding 'custom-no-raw-sql' in output, got: %s", output)
	}
	if !strings.Contains(output, "String concatenation in SQL queries") {
		t.Errorf("expected custom rule message in output, got: %s", output)
	}
}

func TestReviewWithInvalidCustomRulesFails(t *testing.T) {
	repoDir := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, output)
		}
	}

	runGit("init")
	runGit("config", "user.name", "Test User")
	runGit("config", "user.email", "test@example.com")

	badRules := `version: "1.0"
rules:
  - id: "invalid id with spaces"
    name: "Bad rule"
    severity: high
    category: security
    message: "Invalid"
    pattern: 'test'
`
	badPath := filepath.Join(repoDir, "bad-rules.yaml")
	if err := os.WriteFile(badPath, []byte(badRules), 0644); err != nil {
		t.Fatal(err)
	}

	// Stage a file so review runs
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "main.go")

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	_, reviewErr := captureOutput(func() error {
		return executeWithArgs("review", []string{"--rules", badPath})
	})

	if reviewErr == nil {
		t.Fatalf("expected error from invalid custom rules schema, got nil")
	}
	if !strings.Contains(reviewErr.Error(), "letters, numbers, underscores, and hyphens") {
		t.Errorf("expected error message to explain schema validation failure, got: %v", reviewErr)
	}
}

func TestExplainFrameworkRule(t *testing.T) {
	output, err := captureOutput(func() error {
		return executeWithArgs("explain", []string{"gin-unhandled-binding"})
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "gin-unhandled-binding") || !strings.Contains(output, "_ = c.BindJSON(&req)") {
		t.Errorf("unexpected explain output: %s", output)
	}
}
