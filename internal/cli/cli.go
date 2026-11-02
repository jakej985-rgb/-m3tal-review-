package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

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

	return execute(command)
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

		engine := review.NewEngine(review.TodoRule{})
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
	fmt.Println("  help")
}
// TODO: test review report
