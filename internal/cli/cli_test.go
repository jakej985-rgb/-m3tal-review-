package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestCheckDisplaysChangedAndUntrackedFiles(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	trackedPath := filepath.Join(repoDir, "tracked.txt")
	if err := os.WriteFile(trackedPath, []byte("initial"), 0644); err != nil {
		t.Fatalf("write tracked file: %v", err)
	}

	add := exec.Command("git", "-C", repoDir, "add", "tracked.txt")
	if output, err := add.CombinedOutput(); err != nil {
		t.Fatalf("stage tracked file: %v\n%s", err, output)
	}

	commit := exec.Command(
		"git", "-C", repoDir,
		"-c", "user.name=Test User",
		"-c", "user.email=test@example.com",
		"commit", "-m", "initial commit",
	)
	if output, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("create initial commit: %v\n%s", err, output)
	}

	if err := os.WriteFile(trackedPath, []byte("modified"), 0644); err != nil {
		t.Fatalf("modify tracked file: %v", err)
	}

	untrackedPath := filepath.Join(repoDir, "new-file.txt")
	if err := os.WriteFile(untrackedPath, []byte("new"), 0644); err != nil {
		t.Fatalf("write untracked file: %v", err)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create output pipe: %v", err)
	}

	originalStdout := os.Stdout
	os.Stdout = writer

	executeErr := execute("check")

	os.Stdout = originalStdout
	if err := writer.Close(); err != nil {
		t.Fatalf("close output writer: %v", err)
	}

	var captured strings.Builder
	buffer := make([]byte, 1024)
	for {
		n, readErr := reader.Read(buffer)
		captured.Write(buffer[:n])

		if readErr != nil {
			break
		}
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close output reader: %v", err)
	}

	if executeErr != nil {
		t.Fatalf("execute(check) error: %v", executeErr)
	}

	outputText := captured.String()

	if !strings.Contains(outputText, "tracked.txt") {
		t.Errorf("check output does not contain tracked file:\n%s", outputText)
	}

	if !strings.Contains(outputText, "new-file.txt") {
		t.Errorf("check output does not contain untracked file:\n%s", outputText)
	}
}

func TestRunShowRequiresRunID(t *testing.T) {
	err := Run([]string{"show"})

	if err == nil {
		t.Fatal("Run(show) expected an error when run ID is missing")
	}

	if !strings.Contains(err.Error(), "usage: m3tal-review show <run-id>") {
		t.Errorf("Run(show) error = %v, want usage message", err)
	}
}

func TestRunShowUnknownReport(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	err = Run([]string{"show", "ffffffffffffffff"})
	if err == nil {
		t.Fatal("Run(show) expected an error for an unknown report")
	}
}

func TestRunShowDisplaysReport(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	runID := "a1b2c3d4e5f60718"

	report := review.NewReport(
		runID,
		repoDir,
		"main",
		"sha",
		"basesha",
		"hash",
		"ver",
		nil,
		nil,
	)

	reportPath := filepath.Join(
		repoDir,
		".m3tal-review",
		"reports",
		runID+".json",
	)

	if err := review.WriteReport(reportPath, report); err != nil {
		t.Fatalf("write report: %v", err)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create output pipe: %v", err)
	}

	originalStdout := os.Stdout
	os.Stdout = writer

	runErr := Run([]string{"show", runID})

	os.Stdout = originalStdout

	if err := writer.Close(); err != nil {
		t.Fatalf("close output writer: %v", err)
	}

	var captured strings.Builder
	buffer := make([]byte, 1024)

	for {
		n, readErr := reader.Read(buffer)
		captured.Write(buffer[:n])

		if readErr != nil {
			break
		}
	}

	if err := reader.Close(); err != nil {
		t.Fatalf("close output reader: %v", err)
	}

	if runErr != nil {
		t.Fatalf("Run(show) error: %v", runErr)
	}

	outputText := captured.String()

	if !strings.Contains(outputText, "M3TAL Review Report") {
		t.Errorf("output missing report heading:\n%s", outputText)
	}

	if !strings.Contains(outputText, runID) {
		t.Errorf("output missing run ID:\n%s", outputText)
	}

	if !strings.Contains(outputText, "Findings: (none)") {
		t.Errorf("output missing empty findings message:\n%s", outputText)
	}
}

func TestRunShowDisplaysRemediation(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	runID := "b2c3d4e5f6071829"

	findings := []review.Finding{
		{
			Rule:        "hardcoded-credential",
			Severity:    "high",
			File:        "config.go",
			Line:        15,
			Message:     "Possible hardcoded credential assigned to password",
			Remediation: "Remove hardcoded credentials. Use environment variables.",
		},
	}

	report := review.NewReport(
		runID,
		repoDir,
		"main",
		"commit-sha-123",
		"",
		"",
		"1.0.0",
		[]string{"config.go"},
		findings,
	)

	reportPath := filepath.Join(
		repoDir,
		".m3tal-review",
		"reports",
		runID+".json",
	)

	if err := review.WriteReport(reportPath, report); err != nil {
		t.Fatalf("write report: %v", err)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create output pipe: %v", err)
	}

	originalStdout := os.Stdout
	os.Stdout = writer

	runErr := Run([]string{"show", runID})

	os.Stdout = originalStdout

	if err := writer.Close(); err != nil {
		t.Fatalf("close output writer: %v", err)
	}

	var captured strings.Builder
	buffer := make([]byte, 1024)

	for {
		n, readErr := reader.Read(buffer)
		captured.Write(buffer[:n])

		if readErr != nil {
			break
		}
	}

	if err := reader.Close(); err != nil {
		t.Fatalf("close output reader: %v", err)
	}

	if runErr != nil {
		t.Fatalf("Run(show) error: %v", runErr)
	}

	outputText := captured.String()

	if !strings.Contains(outputText, "[high] config.go:15: Possible hardcoded credential assigned to password (hardcoded-credential)") {
		t.Errorf("output missing finding line:\n%s", outputText)
	}

	if !strings.Contains(outputText, "Remediation: Remove hardcoded credentials. Use environment variables.") {
		t.Errorf("output missing finding remediation:\n%s", outputText)
	}
}

func TestRunShowRejectsInvalidRunID(t *testing.T) {
	tests := []string{
		"",
		"short",
		"../../etc/passwd",
		"08D28520B0879CEE",
		"not-a-valid-run-id",
	}

	for _, runID := range tests {
		t.Run(runID, func(t *testing.T) {
			err := showReport(runID)

			if err == nil {
				t.Fatalf("showReport(%q) expected an error", runID)
			}

			if !strings.Contains(err.Error(), "invalid run ID") {
				t.Errorf("showReport(%q) error = %v, want invalid run ID error", runID, err)
			}
		})
	}
}

func TestRunShowDisplaysUnanalyzedFiles(t *testing.T) {
	repoDir := t.TempDir()
	if output, err := exec.Command("git", "init", repoDir).CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v\n%s", err, output)
	}
	const runID = "0123456789abcdef"
	report := review.NewReport(runID, repoDir, "main", "sha", "", "", "1.0.0", []string{"asset.bin"}, nil)
	report.UnanalyzedFiles = []string{"asset.bin"}
	report.Findings = []review.Finding{{Rule: "test", Severity: "low", File: "bad\x1b]52;c;payload.go", Line: 1, Message: "test finding"}}
	report.Passed = false
	report.Summary = "Review incomplete. Some staged files could not be analyzed."
	path := filepath.Join(repoDir, ".m3tal-review", "reports", runID+".json")
	if err := review.WriteReport(path, report); err != nil {
		t.Fatal(err)
	}
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalDir) })
	output, err := captureOutput(func() error { return Run([]string{"show", runID}) })
	if err != nil {
		t.Fatalf("Run(show) error: %v", err)
	}
	if !strings.Contains(output, "Not fully analyzed (binary, unsupported source language, submodule, or file-mode changes):") || !strings.Contains(output, "asset.bin") {
		t.Fatalf("show output omitted unanalyzed files:\n%s", output)
	}
	if strings.ContainsAny(output, "\x1b") || !strings.Contains(output, `bad\x1b]52;c;payload.go`) {
		t.Fatalf("show output did not safely escape the control character in the path:\n%q", output)
	}
}

func setupLintRepo(t *testing.T, source string) string {
	t.Helper()

	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	if err := os.WriteFile(
		filepath.Join(repoDir, "go.mod"),
		[]byte("module lint-test\n\ngo 1.23\n"),
		0644,
	); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	if err := os.WriteFile(
		filepath.Join(repoDir, "main.go"),
		[]byte(source),
		0644,
	); err != nil {
		t.Fatalf("write main.go: %v", err)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("change working directory: %v", err)
	}

	t.Cleanup(func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	return repoDir
}

func captureLintOutput(t *testing.T) (string, error) {
	t.Helper()

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create output pipe: %v", err)
	}

	originalStdout := os.Stdout
	os.Stdout = writer

	runErr := execute("lint")

	os.Stdout = originalStdout

	if err := writer.Close(); err != nil {
		t.Fatalf("close output writer: %v", err)
	}

	var captured strings.Builder
	buffer := make([]byte, 1024)

	for {
		n, readErr := reader.Read(buffer)
		captured.Write(buffer[:n])

		if readErr != nil {
			break
		}
	}

	if err := reader.Close(); err != nil {
		t.Fatalf("close output reader: %v", err)
	}

	return captured.String(), runErr
}

func TestLintPassesCleanGoProject(t *testing.T) {
	setupLintRepo(t, `package main

func main() {
	println("hello")
}
`)

	output, err := captureLintOutput(t)
	if err != nil {
		t.Fatalf("execute(lint) error: %v\n%s", err, output)
	}

	if !strings.Contains(output, "Formatting passed.") {
		t.Errorf("output missing formatting success:\n%s", output)
	}

	if !strings.Contains(output, "go vet passed.") {
		t.Errorf("output missing go vet success:\n%s", output)
	}
}

func TestLintFailsOnUnformattedGoFile(t *testing.T) {
	setupLintRepo(t, `package main
func main(){println("hello")}
`)

	output, err := captureLintOutput(t)
	if err == nil {
		t.Fatalf("execute(lint) expected an error for unformatted source:\n%s", output)
	}

	if !strings.Contains(output, "Files need formatting:") {
		t.Errorf("output missing formatting failure:\n%s", output)
	}
}

func TestReviewRecordsSecurityFindings(t *testing.T) {
	repoDir := setupLintRepo(t, `package main

func main() {
	password := "supersecretpassword"
	println(password)
}
`)

	add := exec.Command("git", "-C", repoDir, "add", "go.mod", "main.go")
	if output, err := add.CombinedOutput(); err != nil {
		t.Fatalf("stage test files: %v\n%s", err, output)
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create output pipe: %v", err)
	}

	originalStdout := os.Stdout
	os.Stdout = writer
	reviewErr := execute("review")
	os.Stdout = originalStdout

	if err := writer.Close(); err != nil {
		t.Fatalf("close output writer: %v", err)
	}

	var captured strings.Builder
	buffer := make([]byte, 1024)
	for {
		n, readErr := reader.Read(buffer)
		captured.Write(buffer[:n])
		if readErr != nil {
			break
		}
	}

	if err := reader.Close(); err != nil {
		t.Fatalf("close output reader: %v", err)
	}

	outputText := captured.String()
	if reviewErr == nil {
		t.Fatalf("execute(review) expected security finding, got nil\n%s", outputText)
	}

	var runID string
	for _, line := range strings.Split(outputText, "\n") {
		if strings.HasPrefix(line, "Run ID:") {
			runID = strings.TrimSpace(strings.TrimPrefix(line, "Run ID:"))
			break
		}
	}
	if runID == "" {
		t.Fatalf("could not extract run ID:\n%s", outputText)
	}

	reportPath := filepath.Join(
		repoDir,
		".m3tal-review",
		"reports",
		runID+".json",
	)

	report, err := review.ReadReport(reportPath)
	if err != nil {
		t.Fatalf("read review report: %v", err)
	}

	found := false
	for _, finding := range report.Findings {
		if finding.Rule == "hardcoded-credential" &&
			finding.File == "main.go" &&
			finding.Line == 4 {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("report missing expected security finding: %+v", report.Findings)
	}
}

func TestReviewRecordsSlopFindings(t *testing.T) {
	repoDir := setupLintRepo(t, `package main

func main() {
	isValid := true
	if isValid == true {
		println("Slop!")
	}
}

`)

	add := exec.Command("git", "-C", repoDir, "add", "go.mod", "main.go")
	if output, err := add.CombinedOutput(); err != nil {
		t.Fatalf("stage test files: %v\n%s", err, output)
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create output pipe: %v", err)
	}

	originalStdout := os.Stdout
	os.Stdout = writer
	reviewErr := execute("review")
	os.Stdout = originalStdout

	if err := writer.Close(); err != nil {
		t.Fatalf("close output writer: %v", err)
	}

	var captured strings.Builder
	buffer := make([]byte, 1024)
	for {
		n, readErr := reader.Read(buffer)
		captured.Write(buffer[:n])
		if readErr != nil {
			break
		}
	}

	if err := reader.Close(); err != nil {
		t.Fatalf("close output reader: %v", err)
	}

	outputText := captured.String()
	if reviewErr == nil {
		t.Fatalf("execute(review) expected slop finding, got nil\n%s", outputText)
	}

	if !strings.Contains(outputText, "Remediation: Remove the explicit comparison") {
		t.Errorf("expected remediation output, got: \n%s", outputText)
	}

	var runID string
	for _, line := range strings.Split(outputText, "\n") {
		if strings.HasPrefix(line, "Run ID:") {
			runID = strings.TrimSpace(strings.TrimPrefix(line, "Run ID:"))
			break
		}
	}
	if runID == "" {
		t.Fatalf("could not extract run ID:\n%s", outputText)
	}

	reportPath := filepath.Join(
		repoDir,
		".m3tal-review",
		"reports",
		runID+".json",
	)

	report, err := review.ReadReport(reportPath)
	if err != nil {
		t.Fatalf("read review report: %v", err)
	}

	found := false
	for _, finding := range report.Findings {
		if finding.Rule == "code-slop" &&
			finding.File == "main.go" {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("report missing expected code-slop finding: %+v", report.Findings)
	}
}

func TestLintVsReviewSeparation(t *testing.T) {
	repoDir := t.TempDir()

	runGit := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v error: %v\n%s", args, err, out)
		}
	}

	runGit("init")
	runGit("config", "user.name", "Test User")
	runGit("config", "user.email", "test@example.com")

	if err := os.WriteFile(filepath.Join(repoDir, "go.mod"), []byte("module testmod\n\ngo 1.23\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\n\nfunc main() {\n\tprintln(\"hello\")\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", ".")
	runGit("commit", "-m", "initial")

	// Create an unstaged file with terrible formatting that fails gofmt
	badFormatFile := filepath.Join(repoDir, "unstaged_bad.go")
	if err := os.WriteFile(badFormatFile, []byte("package   main\n\nfunc    bad(  )   {\n\tprintln(\"bad\")\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Stage a clean change in main.go
	cleanMain := "package main\n\nfunc main() {\n\tprintln(\"hello\")\n}\nfunc cleanHelper() {\n\tprintln(\"helper\")\n}\n"
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte(cleanMain), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "main.go")

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalDir)
	})

	// 1. review should succeed because staged changes in main.go are clean
	reviewErr := execute("review")
	if reviewErr != nil {
		t.Fatalf("review expected to pass staged-only check, got error: %v", reviewErr)
	}

	// 2. lint should fail because unstaged_bad.go is not formatted with gofmt
	lintErr := execute("lint")
	if lintErr == nil {
		t.Fatalf("lint expected to fail repository-wide check due to unformatted file, but passed")
	}
}

func TestReviewHandlesMissingCommitMetadataUnbornBranch(t *testing.T) {
	repoDir := t.TempDir()

	runGit := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v error: %v\n%s", args, err, out)
		}
	}

	runGit("init")
	runGit("config", "user.name", "Test User")
	runGit("config", "user.email", "test@example.com")

	cleanMain := "package main\n\nfunc main() {\n\tprintln(\"unborn\")\n}\n"
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte(cleanMain), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "main.go")

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalDir)
	})

	// Capture stdout
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = stdoutW

	// Capture stderr
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStderr := os.Stderr
	os.Stderr = stderrW

	reviewErr := execute("review")

	os.Stdout = origStdout
	os.Stderr = origStderr
	stdoutW.Close()
	stderrW.Close()

	var stdoutBuf, stderrBuf strings.Builder
	buf := make([]byte, 1024)
	for {
		n, rerr := stdoutR.Read(buf)
		stdoutBuf.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	for {
		n, rerr := stderrR.Read(buf)
		stderrBuf.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	stdoutR.Close()
	stderrR.Close()

	if reviewErr != nil {
		t.Fatalf("review on unborn branch returned unexpected error: %v", reviewErr)
	}

	stderrOut := stderrBuf.String()
	if !strings.Contains(stderrOut, "Warning: unable to determine current commit SHA") {
		t.Errorf("expected warning in stderr about commit SHA, got:\n%s", stderrOut)
	}

	stdoutOut := stdoutBuf.String()
	var runID string
	for _, line := range strings.Split(stdoutOut, "\n") {
		if strings.HasPrefix(line, "Run ID:") {
			runID = strings.TrimSpace(strings.TrimPrefix(line, "Run ID:"))
			break
		}
	}
	if runID == "" {
		t.Fatalf("could not extract run ID from stdout:\n%s", stdoutOut)
	}

	reportPath := filepath.Join(repoDir, ".m3tal-review", "reports", runID+".json")
	report, err := review.ReadReport(reportPath)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}
	if report.CommitSHA != "unavailable" {
		t.Errorf("expected CommitSHA == 'unavailable', got %q", report.CommitSHA)
	}
}

func captureOutput(f func() error) (string, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	origStdout := os.Stdout
	os.Stdout = w

	execErr := f()

	os.Stdout = origStdout
	_ = w.Close()

	var buf strings.Builder
	b := make([]byte, 1024)
	for {
		n, rerr := r.Read(b)
		buf.Write(b[:n])
		if rerr != nil {
			break
		}
	}
	_ = r.Close()
	return buf.String(), execErr
}

func TestCLIHelpCommand(t *testing.T) {
	for _, flag := range []string{"help", "--help", "-h", "-help"} {
		t.Run(flag, func(t *testing.T) {
			out, err := captureOutput(func() error {
				return Run([]string{flag})
			})
			if err != nil {
				t.Fatalf("Run(%q) unexpected error: %v", flag, err)
			}
			if !strings.Contains(out, "Available commands:") || !strings.Contains(out, "recover-history") {
				t.Errorf("unexpected help output for %q:\n%s", flag, out)
			}
		})
	}

	// Also verify default with nil args
	outNil, errNil := captureOutput(func() error {
		return Run(nil)
	})
	if errNil != nil {
		t.Fatalf("Run(nil) unexpected error: %v", errNil)
	}
	if !strings.Contains(outNil, "Available commands:") {
		t.Errorf("unexpected help output for nil args:\n%s", outNil)
	}
}

func TestParseReviewAndAuditOptions(t *testing.T) {
	profile, withTools, err := parseReviewOptions([]string{"--profile", "full", "--with-tools"})
	if err != nil || profile != "full" || !withTools {
		t.Fatalf("parseReviewOptions = %q, %t, %v", profile, withTools, err)
	}
	options, err := parseAuditOptions([]string{"--include-ignored", "--profile=full", "--max-files", "20", "--max-bytes=4096", "--with-tools"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.IncludeIgnored || !options.WithTools || options.Profile != "full" || options.MaxFiles != 20 || options.MaxBytes != 4096 {
		t.Fatalf("parsed audit options = %+v", options)
	}
	if _, err := parseAuditOptions([]string{"--max-files", "0"}); err == nil {
		t.Fatal("expected zero file budget to be rejected")
	}
}

func TestOptionalLocalToolsReportMissingBinariesAsIncomplete(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	findings, checks := runOptionalLocalTools(t.TempDir())
	if len(checks) != 3 || len(findings) != 3 {
		t.Fatalf("got %d checks and %d findings; want 3 each", len(checks), len(findings))
	}
	for i, check := range checks {
		if check.Status != "unavailable" {
			t.Errorf("check %q status = %q; want unavailable", check.Name, check.Status)
		}
		if findings[i].Severity != "high" || findings[i].Category != "confidence" {
			t.Errorf("finding for %q = %+v; want high-severity incomplete check", check.Name, findings[i])
		}
	}
}

func TestWorkingTreeSnapshotOptionsIncludeIgnoredFilesAndEnforceBudget(t *testing.T) {
	repo := t.TempDir()
	if output, err := exec.Command("git", "init", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, output)
	}
	for name, body := range map[string]string{
		".gitignore":  "private.env\n",
		"private.env": "password=secret-value\n",
		"main.go":     "package main\nfunc main() {}\n",
	} {
		if err := os.WriteFile(filepath.Join(repo, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	options := defaultAuditOptions()
	_, files, _, err := workingTreeSnapshotWithOptions(repo, options)
	if err != nil {
		t.Fatal(err)
	}
	if containsFile(files, "private.env") {
		t.Fatal("ignored file was included without --include-ignored")
	}
	options.IncludeIgnored = true
	diff, files, unanalyzed, err := workingTreeSnapshotWithOptions(repo, options)
	if err != nil {
		t.Fatal(err)
	}
	if !containsFile(files, "private.env") || !strings.Contains(diff, "password=secret-value") {
		t.Fatalf("ignored file missing from opted-in snapshot; files=%v", files)
	}
	options.MaxBytes = 1
	_, _, unanalyzed, err = workingTreeSnapshotWithOptions(repo, options)
	if err != nil {
		t.Fatal(err)
	}
	if !containsFile(unanalyzed, "main.go") || len(unanalyzed) == 0 {
		t.Fatalf("scan budget did not mark skipped files unanalyzed: %v", unanalyzed)
	}
}

func containsFile(files []string, target string) bool {
	for _, file := range files {
		if file == target {
			return true
		}
	}
	return false
}

func TestCLIVersionCommand(t *testing.T) {
	for _, flag := range []string{"version", "--version", "-v", "-version"} {
		t.Run(flag, func(t *testing.T) {
			out, err := captureOutput(func() error {
				return Run([]string{flag})
			})
			if err != nil {
				t.Fatalf("Run(%q) unexpected error: %v", flag, err)
			}
			if !strings.Contains(out, "Version:") || !strings.Contains(out, "Go:") {
				t.Errorf("unexpected version output for %q:\n%s", flag, out)
			}
		})
	}
}

func TestCLIHistoryCommandEmptyAndPopulated(t *testing.T) {
	repoDir := t.TempDir()
	cmd := exec.Command("git", "init", repoDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v\n%s", err, out)
	}

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
	})

	// 1. Empty history
	out, err := captureOutput(func() error {
		return Run([]string{"history"})
	})
	if err != nil {
		t.Fatalf("Run(history) unexpected error on empty history: %v", err)
	}
	if !strings.Contains(out, "No review history found.") {
		t.Errorf("expected 'No review history found.', got:\n%s", out)
	}

	// 2. Populated history
	historyPath := filepath.Join(repoDir, ".m3tal-review", "history.jsonl")
	entry := review.HistoryEntry{
		RunID:        "0123456789abcdef",
		Status:       "passed",
		FindingCount: 0,
		Summary:      "Review passed. No findings.",
	}
	if err := review.AppendHistory(historyPath, entry); err != nil {
		t.Fatalf("AppendHistory failed: %v", err)
	}

	outPop, errPop := captureOutput(func() error {
		return Run([]string{"history"})
	})
	if errPop != nil {
		t.Fatalf("Run(history) unexpected error on populated history: %v", errPop)
	}
	if !strings.Contains(outPop, "0123456789abcdef") || !strings.Contains(outPop, "findings: 0") {
		t.Errorf("expected history entry in output, got:\n%s", outPop)
	}
}

func TestCLIRecoverHistoryCommand(t *testing.T) {
	repoDir := t.TempDir()
	cmd := exec.Command("git", "init", repoDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v\n%s", err, out)
	}

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
	})

	// 1. Recover when no reports directory
	outNoReports, errNoReports := captureOutput(func() error {
		return Run([]string{"recover-history"})
	})
	if errNoReports != nil {
		t.Fatalf("Run(recover-history) unexpected error when no reports: %v", errNoReports)
	}
	if !strings.Contains(outNoReports, "No reports found to recover.") {
		t.Errorf("expected 'No reports found to recover.', got:\n%s", outNoReports)
	}

	// 2. Recover with valid report
	reportsDir := filepath.Join(repoDir, ".m3tal-review", "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatal(err)
	}

	rep := review.NewReport("0123456789abcdef", repoDir, "main", "sha", "", "", "1.0.0", nil, nil)
	reportPath := filepath.Join(reportsDir, "0123456789abcdef.json")
	if err := review.WriteReport(reportPath, rep); err != nil {
		t.Fatal(err)
	}

	outRecover, errRecover := captureOutput(func() error {
		return Run([]string{"recover-history"})
	})
	if errRecover != nil {
		t.Fatalf("Run(recover-history) unexpected error: %v", errRecover)
	}
	if !strings.Contains(outRecover, "Successfully recovered 1 review entries to history.") {
		t.Errorf("expected recovery success output, got:\n%s", outRecover)
	}
}

func TestCLIUnknownCommand(t *testing.T) {
	out, err := captureOutput(func() error {
		return Run([]string{"unknown-cmd"})
	})
	if err == nil {
		t.Fatalf("expected error for unknown command, got nil")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("expected error message to mention unknown command, got: %v", err)
	}
	if !strings.Contains(out, "Available commands:") {
		t.Errorf("expected help output printed for unknown command, got:\n%s", out)
	}
}

func TestReviewMarksStagedModeChangeAsIncomplete(t *testing.T) {
	repoDir := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}
	runGit("init")
	runGit("config", "user.name", "Test User")
	runGit("config", "user.email", "test@example.com")
	if err := os.WriteFile(filepath.Join(repoDir, "script.sh"), []byte("#!/bin/sh\necho ok\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "script.sh")
	runGit("commit", "-m", "add script")
	runGit("update-index", "--chmod=+x", "script.sh")

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalDir) })

	output, reviewErr := captureOutput(func() error { return execute("review") })
	if reviewErr == nil || !strings.Contains(reviewErr.Error(), "review incomplete") {
		t.Fatalf("review error = %v, want incomplete-analysis error; output:\n%s", reviewErr, output)
	}
	if !strings.Contains(output, "Not fully analyzed (binary, unsupported source language, submodule, or file-mode changes):") || !strings.Contains(output, "script.sh") {
		t.Fatalf("review output omitted the mode-only change:\n%s", output)
	}

	var runID string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Run ID:") {
			runID = strings.TrimSpace(strings.TrimPrefix(line, "Run ID:"))
			break
		}
	}
	if runID == "" {
		t.Fatalf("could not extract run ID:\n%s", output)
	}
	report, err := review.ReadReport(filepath.Join(repoDir, ".m3tal-review", "reports", runID+".json"))
	if err != nil {
		t.Fatalf("read review report: %v", err)
	}
	if report.Passed || !reflect.DeepEqual(report.UnanalyzedFiles, []string{"script.sh"}) {
		t.Fatalf("report did not preserve incomplete mode analysis: %+v", report)
	}
}
func TestReviewMarksStagedBinaryAsIncomplete(t *testing.T) {
	for _, withText := range []bool{false, true} {
		name := "binary-only"
		if withText {
			name = "mixed-text-and-binary"
		}
		t.Run(name, func(t *testing.T) {
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
			if err := os.WriteFile(filepath.Join(repoDir, "README.md"), []byte("baseline\n"), 0644); err != nil {
				t.Fatal(err)
			}
			runGit("add", "README.md")
			runGit("commit", "-m", "initial")
			if err := os.WriteFile(filepath.Join(repoDir, "asset.bin"), []byte{0, 1, 2, 0, 255}, 0644); err != nil {
				t.Fatal(err)
			}
			runGit("add", "asset.bin")
			if withText {
				if err := os.WriteFile(filepath.Join(repoDir, "change.go"), []byte("package main\n\nfunc change() { println(\"ok\") }\n"), 0644); err != nil {
					t.Fatal(err)
				}
				runGit("add", "change.go")
			}

			originalDir, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chdir(repoDir); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chdir(originalDir) })

			output, reviewErr := captureOutput(func() error { return execute("review") })
			if reviewErr == nil || !strings.Contains(reviewErr.Error(), "review incomplete") {
				t.Fatalf("execute(review) error = %v, want incomplete-analysis error; output:\n%s", reviewErr, output)
			}
			if !strings.Contains(output, "asset.bin") || !strings.Contains(output, "Not fully analyzed (binary, unsupported source language, submodule, or file-mode changes):") {
				t.Fatalf("review output did not identify the unsupported file:\n%s", output)
			}

			var runID string
			for _, line := range strings.Split(output, "\n") {
				if strings.HasPrefix(line, "Run ID:") {
					runID = strings.TrimSpace(strings.TrimPrefix(line, "Run ID:"))
				}
			}
			report, err := review.ReadReport(filepath.Join(repoDir, ".m3tal-review", "reports", runID+".json"))
			if err != nil {
				t.Fatalf("read report: %v", err)
			}
			if report.Passed || !reflect.DeepEqual(report.UnanalyzedFiles, []string{"asset.bin"}) {
				t.Fatalf("report does not preserve incomplete analysis state: %+v", report)
			}
			if withText && !reflect.DeepEqual(report.ReviewedFiles, []string{"asset.bin", "change.go"}) {
				t.Fatalf("mixed report reviewed files = %q", report.ReviewedFiles)
			}
		})
	}
}

func TestDefaultRulesIncludeTLSRule(t *testing.T) {
	var found bool
	for _, rule := range defaultRules("") {
		if rule.Name() == (review.TLSRule{}).Name() {
			found = true
		}
	}
	if !found {
		t.Fatal("defaultRules() does not include TLSRule, but the README advertises TLS verification checks")
	}
}

func TestAuditAnalyzesUnstagedAndUntrackedWorkingTreeWithoutChangingIndex(t *testing.T) {
	repoDir := t.TempDir()
	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, output)
		}
		return string(output)
	}
	runGit("init")
	runGit("config", "user.name", "Test User")
	runGit("config", "user.email", "test@example.com")
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\nfunc main() { println(\"ok\") }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, ".gitignore"), []byte(".m3tal-review/\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "main.go", ".gitignore")
	runGit("commit", "-m", "initial")
	// Stage a harmless change, then make a separate unstaged source edit.
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\nfunc main() { println(\"staged\") }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "main.go")
	indexBefore := runGit("diff", "--cached", "--binary")
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\nfunc main() {\n\tvalid := true\n\tif valid == true { println(\"unstaged\") }\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	untracked := "package main\nfunc extra() {\n\tvalid := true\n\tif valid == true { println(\"untracked\") }\n}\n"
	if err := os.WriteFile(filepath.Join(repoDir, "extra.go"), []byte(untracked), 0644); err != nil {
		t.Fatal(err)
	}
	statusBefore := runGit("status", "--porcelain", "-z")
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalDir) })
	output, auditErr := captureOutput(func() error { return execute("audit") })
	if auditErr == nil || !strings.Contains(auditErr.Error(), "audit found") {
		t.Fatalf("audit error = %v, want finding error; output:\n%s", auditErr, output)
	}
	if !strings.Contains(output, "Scope: working-tree") || !strings.Contains(output, "main.go") || !strings.Contains(output, "extra.go") {
		t.Fatalf("audit output omitted scope or working-tree files:\n%s", output)
	}
	if got := runGit("diff", "--cached", "--binary"); got != indexBefore {
		t.Fatalf("audit changed the Git index\nbefore:\n%s\nafter:\n%s", indexBefore, got)
	}
	if got := runGit("status", "--porcelain", "-z"); got != statusBefore {
		t.Fatalf("audit changed Git status\nbefore: %q\nafter: %q", statusBefore, got)
	}
	var runID string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Run ID:") {
			runID = strings.TrimSpace(strings.TrimPrefix(line, "Run ID:"))
		}
	}
	report, err := review.ReadReport(filepath.Join(repoDir, ".m3tal-review", "reports", runID+".json"))
	if err != nil {
		t.Fatalf("read audit report: %v", err)
	}
	if report.Scope != "working-tree" || !reflect.DeepEqual(report.ReviewedFiles, []string{".gitignore", "extra.go", "main.go"}) {
		t.Fatalf("unexpected audit report scope/files: %+v", report)
	}
	var sawMain, sawExtra bool
	for _, finding := range report.Findings {
		if finding.Rule == "code-slop" {
			sawMain = sawMain || finding.File == "main.go"
			sawExtra = sawExtra || finding.File == "extra.go"
		}
	}
	if !sawMain || !sawExtra {
		t.Fatalf("AST findings did not use current contents for both files: %+v", report.Findings)
	}
	entries, err := review.ReadHistory(filepath.Join(repoDir, ".m3tal-review", "history.jsonl"))
	if err != nil || len(entries) != 1 || entries[0].Scope != "working-tree" {
		t.Fatalf("audit history scope = %+v, err = %v", entries, err)
	}
}

func TestAuditScansCleanTrackedFiles(t *testing.T) {
	repoDir := t.TempDir()
	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, output)
		}
		return string(output)
	}
	runGit("init")
	runGit("config", "user.name", "Test User")
	runGit("config", "user.email", "test@example.com")
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\n// TODO: existing cleanup\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, ".gitignore"), []byte(".m3tal-review/\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "main.go", ".gitignore")
	runGit("commit", "-m", "initial")
	statusBefore := runGit("status", "--porcelain", "-z")
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalDir) })
	output, auditErr := captureOutput(func() error { return execute("audit") })
	if auditErr == nil || !strings.Contains(output, "main.go") {
		t.Fatalf("clean-tree audit did not scan the tracked source: err=%v output:\n%s", auditErr, output)
	}
	var runID string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Run ID:") {
			runID = strings.TrimSpace(strings.TrimPrefix(line, "Run ID:"))
		}
	}
	report, err := review.ReadReport(filepath.Join(repoDir, ".m3tal-review", "reports", runID+".json"))
	if err != nil {
		t.Fatalf("read audit report: %v", err)
	}
	if !reflect.DeepEqual(report.ReviewedFiles, []string{".gitignore", "main.go"}) {
		t.Fatalf("clean-tree audit reviewed files = %q", report.ReviewedFiles)
	}
	if got := runGit("status", "--porcelain", "-z"); got != statusBefore {
		t.Fatalf("audit changed clean repository status: before=%q after=%q", statusBefore, got)
	}
	found := false
	for _, finding := range report.Findings {
		if finding.Rule == "todo-marker" && finding.File == "main.go" && finding.Line == 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("clean-tree audit omitted existing TODO: %+v", report.Findings)
	}
}

func TestAuditPreservesUnusualFilenames(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(repoDir, ".gitignore"), []byte(".m3tal-review/\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", ".gitignore")
	runGit("commit", "-m", "initial")
	oddName := "space\tand\nnewline.txt"
	if err := os.WriteFile(filepath.Join(repoDir, oddName), []byte("TODO: keep the filename intact\n"), 0644); err != nil {
		t.Fatal(err)
	}
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalDir) })
	output, auditErr := captureOutput(func() error { return execute("audit") })
	if auditErr == nil || !strings.Contains(output, `space\x09and\x0anewline.txt`) {
		t.Fatalf("audit did not safely display unusual filename: err=%v output:\n%s", auditErr, output)
	}
	var runID string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Run ID:") {
			runID = strings.TrimSpace(strings.TrimPrefix(line, "Run ID:"))
		}
	}
	report, err := review.ReadReport(filepath.Join(repoDir, ".m3tal-review", "reports", runID+".json"))
	if err != nil {
		t.Fatalf("read audit report: %v", err)
	}
	if !reflect.DeepEqual(report.ReviewedFiles, []string{".gitignore", oddName}) {
		t.Fatalf("audit changed unusual filename: %q", report.ReviewedFiles)
	}
}

func TestAuditMarksExternalUntrackedSymlinkIncomplete(t *testing.T) {
	repoDir := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, output)
		}
	}
	runGit("init")
	target := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(target, []byte("outside\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(repoDir, "outside-link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalDir) })
	output, auditErr := captureOutput(func() error { return execute("audit") })
	if auditErr == nil || !strings.Contains(auditErr.Error(), "audit incomplete") || !strings.Contains(output, "outside-link") {
		t.Fatalf("external symlink was not marked incomplete: err=%v output:\n%s", auditErr, output)
	}
}

func TestAuditMarksBinaryUntrackedFilesAndSkipsIgnoredFiles(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(repoDir, ".gitignore"), []byte("*.ignored\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", ".gitignore")
	runGit("commit", "-m", "initial")
	if err := os.WriteFile(filepath.Join(repoDir, "asset.bin"), []byte{0, 1, 2, 255}, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "secret.ignored"), []byte("ignored"), 0644); err != nil {
		t.Fatal(err)
	}
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalDir) })
	output, auditErr := captureOutput(func() error { return execute("audit") })
	if auditErr == nil || !strings.Contains(auditErr.Error(), "audit incomplete") || !strings.Contains(output, "asset.bin") || strings.Contains(output, "secret.ignored") {
		t.Fatalf("binary/ignored file handling is incorrect: err=%v output:\n%s", auditErr, output)
	}
}
