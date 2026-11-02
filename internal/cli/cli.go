package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

var (
	appName = "M3TAL Review"
	version = "1.0.0"
)

func Run(args []string) error {
	command := "help"

	if len(args) > 0 {
		command = args[0]
	}

	if command == "show" {
		if len(args) < 2 {
			return fmt.Errorf("usage: m3tal-review show <run-id>")
		}

		return showReport(args[1])
	}

	return execute(command)
}

func showReport(runID string) error {
	if !review.IsValidRunID(runID) {
		return fmt.Errorf("invalid run ID %q: expected 16 lowercase hexadecimal characters", runID)
	}

	if runID == "" {
		return fmt.Errorf("run ID cannot be empty")
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	repositoryRoot, err := git.RepositoryRoot(workingDir)
	if err != nil {
		return err
	}

	reportPath := filepath.Join(
		repositoryRoot,
		".m3tal-review",
		"reports",
		runID+".json",
	)

	report, err := review.ReadReport(reportPath)
	if err != nil {
		return err
	}

	fmt.Println("M3TAL Review Report")
	fmt.Println("Run ID:", report.RunID)
	fmt.Println("Repository:", report.Repository)
	fmt.Println("Branch:", report.Branch)
	fmt.Println("Summary:", report.Summary)
	fmt.Println("Report:", reportPath)

	if len(report.Findings) == 0 {
		fmt.Println("Findings: (none)")
		return nil
	}

	fmt.Println("Findings:")

	for _, finding := range report.Findings {
		fmt.Printf(
			"[%s] %s:%d: %s (%s)\n",
			finding.Severity,
			finding.File,
			finding.Line,
			finding.Message,
			finding.Rule,
		)
	}

	return nil
}

func execute(command string) error {
	switch command {
	case "version":
		fmt.Println(appName)
		fmt.Println("Version:", version)
		fmt.Println("Go:", runtime.Version())

		return nil

	case "check":
		workingDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("get working directory: %w", err)
		}

		if err := git.Available(); err != nil {
			return err
		}

		repositoryRoot, err := git.RepositoryRoot(workingDir)
		if err != nil {
			return err
		}

		branch, err := git.CurrentBranch(repositoryRoot)
		if err != nil {
			return err
		}

		clean, err := git.IsClean(repositoryRoot)
		if err != nil {
			return err
		}

		changedFiles, err := git.ChangedFiles(repositoryRoot)
		if err != nil {
			return err
		}

		stagedFiles, err := git.StagedFiles(repositoryRoot)
		if err != nil {
			return err
		}

		untrackedFiles, err := git.UntrackedFiles(repositoryRoot)
		if err != nil {
			return err
		}

		fmt.Println("M3TAL Review")
		fmt.Println("Working directory:", workingDir)
		fmt.Println("Repository root:", repositoryRoot)
		fmt.Println("Current branch:", branch)
		fmt.Println("Working tree clean:", clean)
		fmt.Println("Changed tracked files:")
		if len(changedFiles) == 0 {
			fmt.Println("  (none)")
		} else {
			for _, file := range changedFiles {
				fmt.Println("  ", file)
			}
		}
		fmt.Println("Untracked files:")
		if len(untrackedFiles) == 0 {
			fmt.Println("  (none)")
		} else {
			for _, file := range untrackedFiles {
				fmt.Println("  ", file)
			}
		}
		fmt.Println("Staged files:")
		if len(stagedFiles) == 0 {
			fmt.Println("  (none)")
		} else {
			for _, file := range stagedFiles {
				fmt.Println("  ", file)
			}
		}

		return nil

	case "review":
		workingDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("get working directory: %w", err)
		}

		if err := git.Available(); err != nil {
			return err
		}

		repositoryRoot, err := git.RepositoryRoot(workingDir)
		if err != nil {
			return err
		}

		branch, err := git.CurrentBranch(repositoryRoot)
		if err != nil {
			return err
		}

		diff, err := git.StagedDiff(repositoryRoot)
		if err != nil {
			return err
		}

		if diff == "" {
			fmt.Println("No staged changes to review.")
			return nil
		}

		runID, err := review.NewRunID()
		if err != nil {
			return err
		}

		engine := review.NewEngine(
			review.TodoRule{},
			review.DebugRule{},
		)
		findings := engine.Run(diff)

		report := review.NewReport(
			runID,
			repositoryRoot,
			branch,
			findings,
		)

		reportPath := filepath.Join(
			repositoryRoot,
			".m3tal-review",
			"reports",
			runID+".json",
		)

		if err := review.WriteReport(reportPath, report); err != nil {
			return err
		}

		historyPath := filepath.Join(
			repositoryRoot,
			".m3tal-review",
			"history.jsonl",
		)

		historyEntry := review.NewHistoryEntry(report)

		if err := review.AppendHistory(historyPath, historyEntry); err != nil {
			return err
		}

		fmt.Println(report.Summary)
		fmt.Println("Run ID:", report.RunID)
		fmt.Println("Report:", reportPath)

		for _, finding := range report.Findings {
			fmt.Printf(
				"[%s] %s:%d: %s (%s)\n",
				finding.Severity,
				finding.File,
				finding.Line,
				finding.Message,
				finding.Rule,
			)
		}

		if !report.Passed {
			return fmt.Errorf("review found %d issue(s)", len(report.Findings))
		}

		return nil

	case "history":
		workingDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("get working directory: %w", err)
		}

		repositoryRoot, err := git.RepositoryRoot(workingDir)
		if err != nil {
			return err
		}

		historyPath := filepath.Join(
			repositoryRoot,
			".m3tal-review",
			"history.jsonl",
		)

		entries, err := review.ReadHistory(historyPath)
		if err != nil {
			return err
		}

		if len(entries) == 0 {
			fmt.Println("No review history found.")
			return nil
		}

		fmt.Println("M3TAL Review History")

		for _, entry := range entries {
			fmt.Printf(
				"[%s] %s | %s | findings: %d | %s\n",
				entry.Status,
				entry.Timestamp.Format("2006-01-02 15:04:05 UTC"),
				entry.RunID,
				entry.FindingCount,
				entry.Summary,
			)
		}

		return nil

	case "lint":
		workingDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("get working directory: %w", err)
		}

		if err := git.Available(); err != nil {
			return err
		}

		repositoryRoot, err := git.RepositoryRoot(workingDir)
		if err != nil {
			return err
		}

		fmt.Println("M3TAL Review Lint")
		fmt.Println("Repository:", repositoryRoot)

		fmt.Println("Checking Go formatting...")

		formatCmd := exec.Command(
			"gofmt",
			"-l",
			".",
		)
		formatCmd.Dir = repositoryRoot

		formatOutput, err := formatCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("run gofmt: %w\n%s", err, formatOutput)
		}

		if strings.TrimSpace(string(formatOutput)) != "" {
			fmt.Println("Files need formatting:")
			fmt.Print(string(formatOutput))
			return fmt.Errorf("gofmt check failed")
		}

		fmt.Println("Formatting passed.")

		fmt.Println("Running go vet...")
		vetCmd := exec.Command("go", "vet", "./...")
		vetCmd.Dir = repositoryRoot

		vetOutput, err := vetCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("go vet failed: %w\n%s", err, vetOutput)
		}

		if len(vetOutput) > 0 {
			fmt.Print(string(vetOutput))
		}

		fmt.Println("go vet passed.")

		return nil

	case "help":
		printHelp()
		return nil

	default:
		printHelp()
		return fmt.Errorf("unknown command %q", command)
	}
}

func printHelp() {
	fmt.Println(appName)
	fmt.Println("Available commands:")
	fmt.Println("  version")
	fmt.Println("  check")
	fmt.Println("  review")
	fmt.Println("  history")
	fmt.Println("  show <run-id>")
	fmt.Println("  lint")
	fmt.Println("  help")
}
