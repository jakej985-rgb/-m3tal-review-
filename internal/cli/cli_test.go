package cli

import (
	"os"
	"os/exec"
	"path/filepath"
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

func TestReviewRecordsLintFindings(t *testing.T) {
	repoDir := setupLintRepo(t, `package main
func main(){println("hello")}
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
		t.Fatalf("execute(review) expected lint findings, got nil\n%s", outputText)
	}

	if !strings.Contains(outputText, "Run ID:") {
		t.Fatalf("review output missing run ID:\n%s", outputText)
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

	if report.Passed {
		t.Fatal("report.Passed = true, want false")
	}

	foundLintFinding := false
	for _, finding := range report.Findings {
		if finding.Rule == "repository-lint" &&
			finding.File == "main.go" {
			foundLintFinding = true
			break
		}
	}

	if !foundLintFinding {
		t.Errorf("report missing repository-lint finding: %+v", report.Findings)
	}

	historyPath := filepath.Join(
		repoDir,
		".m3tal-review",
		"history.jsonl",
	)

	entries, err := review.ReadHistory(historyPath)
	if err != nil {
		t.Fatalf("read review history: %v", err)
	}

	if len(entries) == 0 {
		t.Fatal("review history is empty")
	}

	lastEntry := entries[len(entries)-1]

	if lastEntry.RunID != runID {
		t.Errorf("history RunID = %q, want %q", lastEntry.RunID, runID)
	}

	if lastEntry.Status != "failed" {
		t.Errorf("history Status = %q, want %q", lastEntry.Status, "failed")
	}

	if lastEntry.FindingCount == 0 {
		t.Error("history FindingCount = 0, want at least 1")
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
