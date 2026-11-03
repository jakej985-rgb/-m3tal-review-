package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode"

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

		return outputSafeError(showReport(args[1]))
	}

	return outputSafeError(execute(command))
}

type safeOutputError struct {
	err error
}

func (e safeOutputError) Error() string { return displayText(e.err.Error()) }
func (e safeOutputError) Unwrap() error { return e.err }

func outputSafeError(err error) error {
	if err == nil {
		return nil
	}
	return safeOutputError{err: err}
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
	fmt.Println("Run ID:", displayText(report.RunID))
	fmt.Println("Repository:", displayText(report.Repository))
	fmt.Println("Branch:", displayText(report.Branch))
	fmt.Println("Summary:", displayText(report.Summary))
	fmt.Println("Report:", displayText(reportPath))
	if len(report.UnanalyzedFiles) > 0 {
		fmt.Println("Not fully analyzed (binary, submodule, or file-mode changes):")
		for _, file := range report.UnanalyzedFiles {
			fmt.Println("  ", displayText(file))
		}
	}

	if len(report.Findings) == 0 {
		fmt.Println("Findings: (none)")
		return nil
	}

	fmt.Println("Findings:")

	for _, finding := range report.Findings {
		fmt.Printf(
			"[%s] %s:%d: %s (%s)\n",
			displayText(finding.Severity),
			displayText(finding.File),
			finding.Line,
			displayText(finding.Message),
			displayText(finding.Rule),
		)
		if finding.Remediation != "" {
			fmt.Printf("  Remediation: %s\n", displayText(finding.Remediation))
		}
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
		fmt.Println("Working directory:", displayText(workingDir))
		fmt.Println("Repository root:", displayText(repositoryRoot))
		fmt.Println("Current branch:", displayText(branch))
		fmt.Println("Working tree clean:", clean)
		fmt.Println("Changed tracked files:")
		if len(changedFiles) == 0 {
			fmt.Println("  (none)")
		} else {
			for _, file := range changedFiles {
				fmt.Println("  ", displayText(file))
			}
		}
		fmt.Println("Untracked files:")
		if len(untrackedFiles) == 0 {
			fmt.Println("  (none)")
		} else {
			for _, file := range untrackedFiles {
				fmt.Println("  ", displayText(file))
			}
		}
		fmt.Println("Staged files:")
		if len(stagedFiles) == 0 {
			fmt.Println("  (none)")
		} else {
			for _, file := range stagedFiles {
				fmt.Println("  ", displayText(file))
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

		stagedFiles, err := git.StagedFiles(repositoryRoot)
		if err != nil {
			return err
		}
		unanalyzedFiles, err := git.StagedBinaryFiles(repositoryRoot)
		if err != nil {
			return err
		}
		submoduleFiles, err := git.StagedSubmoduleFiles(repositoryRoot)
		if err != nil {
			return err
		}
		unanalyzedFiles = append(unanalyzedFiles, submoduleFiles...)
		modeChangedFiles, err := git.StagedModeChangedFiles(repositoryRoot)
		if err != nil {
			return err
		}
		seenUnanalyzed := make(map[string]bool, len(unanalyzedFiles))
		for _, file := range unanalyzedFiles {
			seenUnanalyzed[file] = true
		}
		for _, file := range modeChangedFiles {
			if !seenUnanalyzed[file] {
				unanalyzedFiles = append(unanalyzedFiles, file)
				seenUnanalyzed[file] = true
			}
		}

		runID, err := review.NewRunID()
		if err != nil {
			return err
		}

		engine := review.NewEngine(defaultRules(repositoryRoot)...)

		findings := engine.Run(diff)

		currentSHA, err := git.CurrentCommitSHA(repositoryRoot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: unable to determine current commit SHA: %s\n", displayText(err.Error()))
			currentSHA = "unavailable"
		}
		// tool version is a global `version`

		report := review.NewReport(
			runID,
			repositoryRoot,
			branch,
			currentSHA,
			"", // base commit SHA (future)
			"", // diff hash (future)
			version,
			stagedFiles,
			findings,
		)
		if len(unanalyzedFiles) > 0 {
			report.UnanalyzedFiles = unanalyzedFiles
			report.Passed = false
			report.Summary = "Review incomplete. Some staged files could not be analyzed."
		}

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
			fmt.Fprintf(os.Stderr, "Warning: failed to append to history log (report was successfully saved to %s): %s\n", displayText(reportPath), displayText(err.Error()))
		}

		fmt.Println(displayText(report.Summary))
		fmt.Println("Run ID:", displayText(report.RunID))
		fmt.Println("Report:", displayText(reportPath))
		if len(report.UnanalyzedFiles) > 0 {
			fmt.Println("Not fully analyzed (binary, submodule, or file-mode changes):")
			for _, file := range report.UnanalyzedFiles {
				fmt.Println("  ", displayText(file))
			}
		}

		for _, finding := range report.Findings {
			fmt.Printf(
				"[%s] %s:%d: %s (%s)\n",
				displayText(finding.Severity),
				displayText(finding.File),
				finding.Line,
				displayText(finding.Message),
				displayText(finding.Rule),
			)
			if finding.Remediation != "" {
				fmt.Printf("  Remediation: %s\n", displayText(finding.Remediation))
			}
		}

		if !report.Passed {
			if len(report.UnanalyzedFiles) > 0 && len(report.Findings) == 0 {
				return fmt.Errorf("review incomplete: %d staged file(s) could not be analyzed", len(report.UnanalyzedFiles))
			}
			if len(report.UnanalyzedFiles) > 0 {
				return fmt.Errorf("review found %d issue(s) and could not analyze %d staged file(s)", len(report.Findings), len(report.UnanalyzedFiles))
			}
			return fmt.Errorf("review found %d issue(s)", len(report.Findings))
		}

		return nil

	case "audit":
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
		diff, reviewedFiles, unanalyzedFiles, err := workingTreeSnapshot(repositoryRoot)
		if err != nil {
			return err
		}
		runID, err := review.NewRunID()
		if err != nil {
			return err
		}
		rules := defaultRules(repositoryRoot)
		for i, rule := range rules {
			if slop, ok := rule.(review.SlopRule); ok {
				slop.WorkingTree = true
				rules[i] = slop
			}
		}
		findings := review.NewEngine(rules...).Run(diff)
		currentSHA, err := git.CurrentCommitSHA(repositoryRoot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: unable to determine current commit SHA: %s\n", displayText(err.Error()))
			currentSHA = "unavailable"
		}
		report := review.NewReport(runID, repositoryRoot, branch, currentSHA, "", "", version, reviewedFiles, findings)
		report.Scope = "working-tree"
		if len(unanalyzedFiles) > 0 {
			report.UnanalyzedFiles = unanalyzedFiles
			report.Passed = false
			report.Summary = "Audit incomplete. Some working-tree files could not be analyzed."
		} else if len(findings) > 0 {
			report.Summary = "Audit found findings that require attention."
		}
		reportPath := filepath.Join(repositoryRoot, ".m3tal-review", "reports", runID+".json")
		if err := review.WriteReport(reportPath, report); err != nil {
			return err
		}
		historyPath := filepath.Join(repositoryRoot, ".m3tal-review", "history.jsonl")
		if err := review.AppendHistory(historyPath, review.NewHistoryEntry(report)); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to append to history log (report was successfully saved to %s): %s\n", displayText(reportPath), displayText(err.Error()))
		}
		fmt.Println(displayText(report.Summary))
		fmt.Println("Scope: working-tree")
		fmt.Println("Run ID:", displayText(runID))
		fmt.Println("Report:", displayText(reportPath))
		for _, finding := range report.Findings {
			fmt.Printf("[%s] %s:%d: %s (%s)\n", displayText(finding.Severity), displayText(finding.File), finding.Line, displayText(finding.Message), displayText(finding.Rule))
		}
		if len(report.UnanalyzedFiles) > 0 {
			fmt.Println("Unanalyzed files:")
			for _, file := range report.UnanalyzedFiles {
				fmt.Println("  ", displayText(file))
			}
		}
		if !report.Passed {
			if len(report.UnanalyzedFiles) > 0 {
				return fmt.Errorf("audit incomplete: %d file(s) could not be analyzed", len(report.UnanalyzedFiles))
			}
			return fmt.Errorf("audit found %d issue(s)", len(report.Findings))
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
				displayText(entry.Status),
				entry.Timestamp.Format("2006-01-02 15:04:05 UTC"),
				displayText(entry.RunID),
				entry.FindingCount,
				displayText(entry.Summary),
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
		fmt.Println("Repository:", displayText(repositoryRoot))

		fmt.Println("Checking Go formatting...")

		formatCmd := exec.Command(
			"gofmt",
			"-l",
			".",
		)
		formatCmd.Dir = repositoryRoot

		formatOutput, err := formatCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("run gofmt: %w\n%s", err, displayText(string(formatOutput)))
		}

		if strings.TrimSpace(string(formatOutput)) != "" {
			fmt.Println("Files need formatting:")
			for _, file := range strings.Split(strings.TrimSpace(string(formatOutput)), "\n") {
				fmt.Println(displayText(file))
			}
			return fmt.Errorf("gofmt check failed")
		}

		fmt.Println("Formatting passed.")

		fmt.Println("Running go vet...")
		vetCmd := exec.Command("go", "vet", "./...")
		vetCmd.Dir = repositoryRoot

		vetOutput, err := vetCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("go vet failed: %w\n%s", err, displayText(string(vetOutput)))
		}

		if len(vetOutput) > 0 {
			fmt.Print(displayText(string(vetOutput)))
		}

		fmt.Println("go vet passed.")

		return nil

	case "recover-history":
		workingDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("get working directory: %w", err)
		}

		repositoryRoot, err := git.RepositoryRoot(workingDir)
		if err != nil {
			return err
		}

		reportsDir := filepath.Join(repositoryRoot, ".m3tal-review", "reports")
		historyPath := filepath.Join(repositoryRoot, ".m3tal-review", "history.jsonl")

		recovered, err := review.RecoverHistory(reportsDir, historyPath)
		if err != nil {
			return fmt.Errorf("recover history: %w", err)
		}

		if recovered == 0 {
			fmt.Println("No reports found to recover.")
			return nil
		}

		fmt.Printf("Successfully recovered %d review entries to history.\n", recovered)
		return nil

	case "help":
		printHelp()
		return nil

	default:
		printHelp()
		return fmt.Errorf("unknown command %q", command)
	}
}

// defaultRules returns the rules run by "review". Every staged-diff rule that
// is advertised in the README must be listed here.
func defaultRules(repositoryRoot string) []review.Rule {
	return []review.Rule{
		review.TodoRule{},
		review.DebugRule{},
		review.SecurityRule{},
		review.ShellRule{},
		review.TLSRule{},
		review.PermissionsRule{},
		review.SlopRule{RepositoryRoot: repositoryRoot},
	}
}

func workingTreeSnapshot(repositoryRoot string) (string, []string, []string, error) {
	files, err := git.WorkingTreeFiles(repositoryRoot)
	if err != nil {
		return "", nil, nil, err
	}
	var diff strings.Builder
	fileSet := make(map[string]bool, len(files))
	unanalyzedSet := make(map[string]bool)
	for _, file := range files {
		if file == ".m3tal-review" || strings.HasPrefix(file, ".m3tal-review/") || file == ".git" || strings.HasPrefix(file, ".git/") {
			continue
		}
		if !filepath.IsLocal(file) {
			unanalyzedSet[file] = true
			fileSet[file] = true
			continue
		}
		fullPath := filepath.Join(repositoryRoot, file)
		_, statErr := os.Lstat(fullPath)
		if os.IsNotExist(statErr) {
			continue
		}
		if statErr != nil {
			unanalyzedSet[file] = true
			fileSet[file] = true
			continue
		}
		target, evalErr := filepath.EvalSymlinks(fullPath)
		rel, relErr := filepath.Rel(repositoryRoot, target)
		if evalErr != nil || relErr != nil || !filepath.IsLocal(rel) {
			unanalyzedSet[file] = true
			fileSet[file] = true
			continue
		}
		contentInfo, contentStatErr := os.Stat(fullPath)
		if contentStatErr != nil {
			unanalyzedSet[file] = true
			fileSet[file] = true
			continue
		}
		content, readErr := os.ReadFile(fullPath)
		fileSet[file] = true
		if readErr != nil || !contentInfo.Mode().IsRegular() || strings.IndexByte(string(content), 0) >= 0 {
			unanalyzedSet[file] = true
			continue
		}
		diff.WriteString(untrackedFileDiff(file, content, contentInfo.Mode()))
	}
	unanalyzed := make([]string, 0, len(unanalyzedSet))
	for file := range unanalyzedSet {
		unanalyzed = append(unanalyzed, file)
	}
	sort.Strings(unanalyzed)
	return filterUnanalyzedDiff(diff.String(), unanalyzedSet), sortedKeys(fileSet), unanalyzed, nil
}

func filterUnanalyzedDiff(diff string, unanalyzed map[string]bool) string {
	if len(unanalyzed) == 0 {
		return diff
	}
	var filtered strings.Builder
	var chunk strings.Builder
	flush := func() {
		if chunk.Len() == 0 {
			return
		}
		text := chunk.String()
		parsed := review.ParseDiff(text)
		if len(parsed) == 0 || !unanalyzed[parsed[0].Path] {
			filtered.WriteString(text)
		}
		chunk.Reset()
	}
	for _, line := range strings.SplitAfter(diff, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			flush()
		}
		chunk.WriteString(line)
	}
	flush()
	return filtered.String()
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func untrackedFileDiff(file string, content []byte, mode os.FileMode) string {
	oldPath := strconv.Quote("a/" + file)
	newPath := strconv.Quote("b/" + file)
	quoted := strconv.Quote("b/" + file)
	var b strings.Builder
	gitMode := "100644"
	if mode.Perm()&0o111 != 0 {
		gitMode = "100755"
	}
	fmt.Fprintf(&b, "diff --git %s %s\nnew file mode %s\n--- /dev/null\n+++ %s\n", oldPath, newPath, gitMode, quoted)
	lines := []string{}
	if len(content) > 0 {
		lines = strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	}
	fmt.Fprintf(&b, "@@ -0,0 +1,%d @@\n", len(lines))
	for _, line := range lines {
		b.WriteByte('+')
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func printHelp() {
	fmt.Println(appName)
	fmt.Println("Available commands:")
	fmt.Println("  version")
	fmt.Println("  check")
	fmt.Println("  review")
	fmt.Println("  audit")
	fmt.Println("  history")
	fmt.Println("  show <run-id>")
	fmt.Println("  lint")
	fmt.Println("  recover-history")
	fmt.Println("  help")
}

func displayText(value string) string {
	var displayed strings.Builder
	for _, r := range value {
		if !unicode.IsControl(r) {
			displayed.WriteRune(r)
			continue
		}
		switch {
		case r <= 0xff:
			fmt.Fprintf(&displayed, "\\x%02x", r)
		case r <= 0xffff:
			fmt.Fprintf(&displayed, "\\u%04x", r)
		default:
			fmt.Fprintf(&displayed, "\\U%08x", r)
		}
	}
	return displayed.String()
}
