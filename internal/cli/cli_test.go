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

	err = Run([]string{"show", "unknown-run-id"})
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

	runID := "test-run-123"

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
