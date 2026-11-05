package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

var (
	appName = "M3TAL Review"
	version = "1.0.0"
)

func Run(args []string) error {
	command := "help"
	commandArgs := []string{}

	if len(args) > 0 {
		command = args[0]
		commandArgs = args[1:]
	}

	switch command {
	case "-h", "--help", "-help":
		command = "help"
	case "-v", "--version", "-version":
		command = "version"
	}

	if command == "show" {
		if len(args) < 2 {
			return fmt.Errorf("usage: m3tal-review show <run-id>")
		}

		return outputSafeError(showReport(args[1]))
	}

	return outputSafeError(executeWithArgs(command, commandArgs))
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
	if err := ensureReviewStorageSafe(repositoryRoot, reportPath); err != nil {
		return err
	}

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
	printFindingChanges(report.FindingChanges)
	if len(report.UnanalyzedFiles) > 0 {
		fmt.Println("Not fully analyzed (binary, unsupported source language, submodule, or file-mode changes):")
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
		location := displayText(finding.File)
		if finding.Line > 0 {
			location = fmt.Sprintf("%s:%d", location, finding.Line)
		}
		fmt.Printf(
			"[%s] %s: %s (%s)\n",
			displayText(finding.Severity),
			location,
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
	return executeWithArgs(command, nil)
}

func executeWithArgs(command string, commandArgs []string) error {
	switch command {
	case "version":
		if len(commandArgs) > 0 && commandArgs[0] == "--json" {
			fmt.Printf("{\"name\":\"%s\",\"version\":\"%s\",\"go\":\"%s\"}\n", appName, version, runtime.Version())
			return nil
		}
		fmt.Println(appName)
		fmt.Println("Version:", version)
		fmt.Println("Go:", runtime.Version())

		return nil

	case "list-rules":
		return listRules()

	case "explain":
		if len(commandArgs) != 1 {
			return fmt.Errorf("usage: m3tal-review explain <rule>")
		}
		return explainRule(commandArgs[0])

	case "stdin":
		return commandStdin()

	case "diff":
		return commandDiff(commandArgs)

	case "doctor":
		return commandDoctor()

	case "watch":
		return commandWatch(3 * time.Second)

	case "completions":
		if len(commandArgs) != 1 {
			return fmt.Errorf("usage: m3tal-review completions <bash|zsh|fish>")
		}
		return commandCompletions(commandArgs[0])

	case "install-hook":
		force := len(commandArgs) > 0 && commandArgs[0] == "--force"
		return installHook(force)

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
		options, err := parseReviewOptions(commandArgs)
		if err != nil {
			return err
		}
		cfg, cfgErr := loadUserConfig()
		if cfgErr != nil {
			return cfgErr
		}
		applyUserConfig(&options, cfg)
		profile, withTools := options.Profile, options.WithTools
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

		var diff string
		var stagedFiles, unanalyzedFiles []string
		var stagedStatuses map[string]string
		if options.Base != "" {
			diff, err = git.WorkingTreeDiffAgainst(repositoryRoot, options.Base)
			if err != nil {
				return err
			}
			stagedFiles, err = git.ChangedFilesAgainst(repositoryRoot, options.Base)
			if err != nil {
				return err
			}
			unanalyzedFiles, err = git.BinaryFilesAgainst(repositoryRoot, options.Base)
			if err != nil {
				return err
			}
			stagedStatuses = map[string]string{}
			for _, file := range stagedFiles {
				stagedStatuses[file] = "M"
			}
		} else if options.Unstaged {
			diff, err = git.UnstagedDiff(repositoryRoot)
			if err != nil {
				return err
			}
			stagedFiles, err = git.UnstagedFiles(repositoryRoot)
			if err != nil {
				return err
			}
			stagedStatuses = map[string]string{}
			for _, file := range stagedFiles {
				stagedStatuses[file] = "M"
			}
		} else {
			diff, err = git.StagedDiff(repositoryRoot)
			if err != nil {
				return err
			}
			stagedFiles, err = git.StagedFiles(repositoryRoot)
			if err != nil {
				return err
			}
			unanalyzedFiles, err = git.StagedBinaryFiles(repositoryRoot)
			if err != nil {
				return err
			}
			stagedStatuses, err = git.StagedFileStatuses(repositoryRoot)
			if err != nil {
				return err
			}
		}

		if diff == "" {
			fmt.Println("No staged changes to review.")
			return nil
		}
		if int64(len(diff)) > options.MaxDiffSize {
			return fmt.Errorf("diff exceeds --max-diff-size (%d bytes); re-run with a larger limit or review a smaller change set", options.MaxDiffSize)
		}

		if options.Base == "" {
			for file, status := range stagedStatuses {
				if status != "D" && (language.CodeChecker{}).Language(file) == language.LanguageUnknown && language.IsLikelySourceFile(file) {
					unanalyzedFiles = append(unanalyzedFiles, file)
				}
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
		}

		runID, err := review.NewRunID()
		if err != nil {
			return err
		}

		rules := defaultRules(repositoryRoot)
		if options.Base != "" {
			rules = workingTreeRules(rules)
		}
		rules = filterRules(rules, options.Only, options.Skip)
		engine := review.NewEngine(rules...)

		findings := engine.Run(diff)
		var confidenceChecks []review.CheckResult
		if profile == "full" {
			checkFindings, results := runGoConfidenceChecks(repositoryRoot)
			findings = append(findings, checkFindings...)
			confidenceChecks = results
		}
		if withTools {
			toolFindings, results := runOptionalLocalTools(repositoryRoot)
			findings = append(findings, toolFindings...)
			confidenceChecks = append(confidenceChecks, results...)
		}
		workingTree := options.Base != ""
		findings = review.ApplyFindingFilters(diff, findings, repositoryRoot, workingTree)
		if options.Baseline != "" {
			baseline, err := loadBaseline(options.Baseline)
			if err != nil {
				return err
			}
			findings = filterBaseline(findings, baseline)
		}
		findings = filterFindingsByPath(findings, options.Include, options.Exclude)
		findings = sortFindings(findings, options.SortBy)
		if options.MaxFindings > 0 && len(findings) > options.MaxFindings {
			findings = findings[:options.MaxFindings]
		}
		if options.WriteBaseline != "" {
			if err := writeBaseline(options.WriteBaseline, findings); err != nil {
				return err
			}
			fmt.Println("Baseline written:", displayText(options.WriteBaseline))
		}
		if options.CheckRun {
			if err := postCheckRun(findings, options.CheckRunSHA); err != nil {
				return fmt.Errorf("post check run: %w", err)
			}
			fmt.Println("Check run posted.")
		}

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
			currentSHA,
			diffHash(diff),
			version,
			stagedFiles,
			findings,
		)
		report.Profile = profile
		report.Checks = append(report.Checks, confidenceChecks...)
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
		historyPath := filepath.Join(repositoryRoot, ".m3tal-review", "history.jsonl")
		if err := ensureReviewStorageSafe(repositoryRoot, reportPath, historyPath); err != nil {
			return err
		}
		attachFindingChanges(repositoryRoot, historyPath, &report)

		if err := review.WriteReport(reportPath, report); err != nil {
			return err
		}

		historyEntry := review.NewHistoryEntry(report)

		if err := review.AppendHistory(historyPath, historyEntry); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to append to history log (report was successfully saved to %s): %s\n", displayText(reportPath), displayText(err.Error()))
		}

		fmt.Println(displayText(report.Summary))
		fmt.Println("Profile:", profile)
		printFindingChanges(report.FindingChanges)
		printCheckResults(report.Checks)
		fmt.Println("Security checks are heuristic; see README for coverage and limitations.")
		fmt.Println("Run ID:", displayText(report.RunID))
		fmt.Println("Report:", displayText(reportPath))
		if len(report.UnanalyzedFiles) > 0 {
			fmt.Println("Not fully analyzed (binary, unsupported source language, submodule, or file-mode changes):")
			for _, file := range report.UnanalyzedFiles {
				fmt.Println("  ", displayText(file))
			}
		}

		switch options.Format {
		case "sarif":
			out, err := formatFindingsSarif(report.Findings)
			if err != nil {
				return err
			}
			fmt.Println(out)
		case "github":
			fmt.Print(formatFindingsGitHub(report.Findings))
		case "json":
			out, err := formatFindingsJSON(report.Findings)
			if err != nil {
				return err
			}
			fmt.Println(out)
		case "junit":
			fmt.Print(formatFindingsJUnit(report.Findings))
		case "codeclimate":
			out, err := formatFindingsCodeClimate(report.Findings)
			if err != nil {
				return err
			}
			fmt.Println(out)
		default:
			if options.SummaryOnly {
				break
			}
			for _, finding := range report.Findings {
				location := displayText(finding.File)
				if finding.Line > 0 {
					location = fmt.Sprintf("%s:%d", location, finding.Line)
				}
				fmt.Printf(
					"[%s] %s: %s (%s)\n",
					displayText(finding.Severity),
					location,
					displayText(finding.Message),
					displayText(finding.Rule),
				)
				if finding.Remediation != "" {
					fmt.Printf("  Remediation: %s\n", displayText(finding.Remediation))
				}
			}
		}

		if options.FailOn != "" {
			threshold := severityRank(options.FailOn)
			blocking := 0
			for _, finding := range report.Findings {
				if severityRank(finding.Severity) >= threshold {
					blocking++
				}
			}
			if blocking == 0 && len(report.UnanalyzedFiles) == 0 {
				return nil
			}
			if len(report.UnanalyzedFiles) > 0 {
				return fmt.Errorf("review found %d issue(s) at or above %s and could not analyze %d staged file(s)", blocking, options.FailOn, len(report.UnanalyzedFiles))
			}
			return fmt.Errorf("review found %d issue(s) at or above %s", blocking, options.FailOn)
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
		options, err := parseAuditOptions(commandArgs)
		if err != nil {
			return err
		}
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
		runID, err := review.NewRunID()
		if err != nil {
			return err
		}
		rules := filterRules(workingTreeRules(defaultRules(repositoryRoot)), options.Only, options.Skip)
		findings, reviewedFiles, unanalyzedFiles, snapshotHash, err := analyzeWorkingTree(repositoryRoot, options, rules)
		if err != nil {
			return err
		}
		if options.Baseline != "" {
			baseline, err := loadBaseline(options.Baseline)
			if err != nil {
				return err
			}
			findings = filterBaseline(findings, baseline)
		}
		if options.WriteBaseline != "" {
			if err := writeBaseline(options.WriteBaseline, findings); err != nil {
				return err
			}
			fmt.Println("Baseline written:", displayText(options.WriteBaseline))
		}
		var confidenceChecks []review.CheckResult
		if options.Profile == "full" {
			checkFindings, results := runGoConfidenceChecks(repositoryRoot)
			findings = append(findings, checkFindings...)
			confidenceChecks = results
		}
		if options.WithTools {
			toolFindings, results := runOptionalLocalTools(repositoryRoot)
			findings = append(findings, toolFindings...)
			confidenceChecks = append(confidenceChecks, results...)
		}
		currentSHA, err := git.CurrentCommitSHA(repositoryRoot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: unable to determine current commit SHA: %s\n", displayText(err.Error()))
			currentSHA = "unavailable"
		}
		report := review.NewReport(runID, repositoryRoot, branch, currentSHA, currentSHA, snapshotHash, version, reviewedFiles, findings)
		report.Profile = options.Profile
		report.Checks = append(report.Checks, confidenceChecks...)
		report.Scope = "working-tree"
		if len(unanalyzedFiles) > 0 {
			report.UnanalyzedFiles = unanalyzedFiles
			report.Passed = false
			report.Summary = "Audit incomplete. Some working-tree files could not be analyzed."
		} else if !report.Passed {
			report.Summary = "Audit found findings that require attention."
		} else if len(findings) > 0 {
			report.Summary = "Audit passed with informational risk signals."
		}
		reportPath := filepath.Join(repositoryRoot, ".m3tal-review", "reports", runID+".json")
		historyPath := filepath.Join(repositoryRoot, ".m3tal-review", "history.jsonl")
		if err := ensureReviewStorageSafe(repositoryRoot, reportPath, historyPath); err != nil {
			return err
		}
		attachFindingChanges(repositoryRoot, historyPath, &report)
		if err := review.WriteReport(reportPath, report); err != nil {
			return err
		}
		if err := review.AppendHistory(historyPath, review.NewHistoryEntry(report)); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to append to history log (report was successfully saved to %s): %s\n", displayText(reportPath), displayText(err.Error()))
		}
		fmt.Println(displayText(report.Summary))
		fmt.Println("Scope: working-tree")
		fmt.Println("Profile:", options.Profile)
		printFindingChanges(report.FindingChanges)
		printCheckResults(report.Checks)
		fmt.Printf("Scan limits: %d files, %d bytes; ignored files included: %t\n", options.MaxFiles, options.MaxBytes, options.IncludeIgnored)
		fmt.Println("Security checks are heuristic; see README for coverage and limitations.")
		fmt.Println("Run ID:", displayText(runID))
		fmt.Println("Report:", displayText(reportPath))
		switch options.Format {
		case "sarif":
			out, err := formatFindingsSarif(report.Findings)
			if err != nil {
				return err
			}
			fmt.Println(out)
		case "github":
			fmt.Print(formatFindingsGitHub(report.Findings))
		case "json":
			out, err := formatFindingsJSON(report.Findings)
			if err != nil {
				return err
			}
			fmt.Println(out)
		case "junit":
			fmt.Print(formatFindingsJUnit(report.Findings))
		case "codeclimate":
			out, err := formatFindingsCodeClimate(report.Findings)
			if err != nil {
				return err
			}
			fmt.Println(out)
		default:
			for _, finding := range report.Findings {
				location := displayText(finding.File)
				if finding.Line > 0 {
					location = fmt.Sprintf("%s:%d", location, finding.Line)
				}
				fmt.Printf("[%s] %s: %s (%s)\n", displayText(finding.Severity), location, displayText(finding.Message), displayText(finding.Rule))
			}
		}
		if options.FailOn != "" {
			threshold := severityRank(options.FailOn)
			blocking := 0
			for _, finding := range report.Findings {
				if severityRank(finding.Severity) >= threshold {
					blocking++
				}
			}
			if blocking > 0 || len(report.UnanalyzedFiles) > 0 {
				return fmt.Errorf("audit found %d issue(s) at or above %s", blocking, options.FailOn)
			}
			return nil
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
		if err := ensureReviewStorageSafe(repositoryRoot, historyPath); err != nil {
			return err
		}

		entries, err := review.ReadHistory(historyPath)
		if err != nil {
			return err
		}

		if len(entries) == 0 {
			fmt.Println("No review history found.")
			return nil
		}

		// history show <run-id> / history <run-id> prints a stored report.
		if len(commandArgs) >= 1 && (commandArgs[0] == "show" || !strings.HasPrefix(commandArgs[0], "-")) {
			runID := commandArgs[0]
			if runID == "show" {
				if len(commandArgs) < 2 {
					return fmt.Errorf("usage: m3tal-review history show <run-id>")
				}
				runID = commandArgs[1]
			}
			return commandHistoryShow(repositoryRoot, runID)
		}

		// Optional filters: history [--last N] [--status S] [--scope S] [--grep text] [--format json]
		last, statusFilter, scopeFilter, grepFilter := 0, "", "", ""
		formatJSON := false
		for i := 0; i < len(commandArgs); i++ {
			arg := commandArgs[i]
			if i+1 >= len(commandArgs) {
				return fmt.Errorf("history option %q requires a value", arg)
			}
			i++
			v := commandArgs[i]
			switch arg {
			case "--last":
				n, err := strconv.Atoi(v)
				if err != nil || n < 1 {
					return fmt.Errorf("invalid --last %q", v)
				}
				last = n
			case "--status":
				statusFilter = v
			case "--scope":
				scopeFilter = v
			case "--grep":
				grepFilter = strings.ToLower(v)
			case "--format":
				if v != "json" {
					return fmt.Errorf("invalid --format %q; expected json", v)
				}
				formatJSON = true
			default:
				return fmt.Errorf("unknown history option %q", arg)
			}
		}

		shown := 0
		var jsonOut []review.HistoryEntry
		if formatJSON {
			jsonOut = []review.HistoryEntry{}
		} else {
			fmt.Println("M3TAL Review History")
		}
		// Entries are chronological; --last shows the most recent N.
		for idx := len(entries) - 1; idx >= 0; idx-- {
			entry := entries[idx]
			if statusFilter != "" && entry.Status != statusFilter {
				continue
			}
			if scopeFilter != "" && entry.Scope != scopeFilter {
				continue
			}
			if grepFilter != "" {
				hay := strings.ToLower(entry.Summary + " " + entry.RunID)
				if !strings.Contains(hay, grepFilter) {
					continue
				}
			}
			if last > 0 && shown >= last {
				break
			}
			shown++
			if formatJSON {
				jsonOut = append(jsonOut, entry)
				continue
			}
			fmt.Printf(
				"[%s] %s | %s | findings: %d | %s\n",
				displayText(entry.Status),
				entry.Timestamp.Format("2006-01-02 15:04:05 UTC"),
				displayText(entry.RunID),
				entry.FindingCount,
				displayText(entry.Summary),
			)
		}
		if formatJSON {
			out, err := json.MarshalIndent(jsonOut, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(out))
		} else if shown == 0 {
			fmt.Println("No history entries match the filters.")
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

		formatOutput, err := runCommand(context.Background(), repositoryRoot, "gofmt", "-l", ".")
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
		vetOutput, err := runCommand(context.Background(), repositoryRoot, "go", "vet", "./...")
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
		if err := ensureReviewStorageSafe(repositoryRoot, reportsDir, historyPath); err != nil {
			return err
		}

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
	rules := []review.Rule{
		review.TodoRule{RepositoryRoot: repositoryRoot},
		review.DebugRule{RepositoryRoot: repositoryRoot},
		review.RiskRule{RepositoryRoot: repositoryRoot},
		review.PolicyRule{RepositoryRoot: repositoryRoot},
		review.SecurityRule{RepositoryRoot: repositoryRoot},
		review.ShellRule{RepositoryRoot: repositoryRoot},
		review.TLSRule{RepositoryRoot: repositoryRoot},
		review.PermissionsRule{RepositoryRoot: repositoryRoot},
		review.SlopRule{RepositoryRoot: repositoryRoot},
		review.SecretRule{RepositoryRoot: repositoryRoot},
		review.TraversalRule{RepositoryRoot: repositoryRoot},
		review.CryptoRule{RepositoryRoot: repositoryRoot},
		review.DeserializationRule{RepositoryRoot: repositoryRoot},
		review.EvalRule{RepositoryRoot: repositoryRoot},
		review.XSSRule{RepositoryRoot: repositoryRoot},
		review.SQLiRule{RepositoryRoot: repositoryRoot},
	}
	return append(rules, review.ExtraRules(repositoryRoot)...)
}

func runGoConfidenceChecks(repositoryRoot string) ([]review.Finding, []review.CheckResult) {
	commands := []struct {
		name string
		args []string
	}{
		{name: "gofmt", args: []string{"gofmt", "-l", "."}},
		{name: "go vet", args: []string{"go", "vet", "./..."}},
		{name: "go test", args: []string{"go", "test", "./..."}},
	}
	var findings []review.Finding
	results := make([]review.CheckResult, 0, len(commands))
	for _, item := range commands {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		output, err := runCommand(ctx, repositoryRoot, item.args...)
		timedOut := ctx.Err() == context.DeadlineExceeded
		cancel()
		if err != nil {
			message := strings.TrimSpace(string(output))
			if timedOut {
				message = "command exceeded the 5 minute time limit"
			} else if message == "" {
				message = err.Error()
			}
			if len(message) > 12000 {
				message = message[:12000] + "… (output truncated)"
			}
			results = append(results, review.CheckResult{Name: item.name, Category: "confidence", Status: "failed", Message: message})
			findings = append(findings, review.Finding{Category: "confidence", Rule: "confidence-" + strings.ReplaceAll(item.name, " ", "-"), Severity: "high", Message: item.name + " failed: " + message, Remediation: "Resolve the reported validation failure and rerun the full profile."})
			continue
		}
		if item.name == "gofmt" && strings.TrimSpace(string(output)) != "" {
			files := strings.Split(strings.TrimSpace(string(output)), "\n")
			for _, file := range files {
				findings = append(findings, review.Finding{Category: "confidence", Rule: "confidence-gofmt", Severity: "medium", File: filepath.ToSlash(file), Message: "File is not formatted; run gofmt", Remediation: "Run gofmt on the listed files."})
			}
			results = append(results, review.CheckResult{Name: item.name, Category: "confidence", Status: "failed", Message: strings.Join(files, ", ")})
			continue
		}
		results = append(results, review.CheckResult{Name: item.name, Category: "confidence", Status: "passed"})
	}
	return findings, results
}

func printCheckResults(checks []review.CheckResult) {
	for _, check := range checks {
		fmt.Printf("Check [%s] %s", displayText(check.Status), displayText(check.Name))
		if check.Message != "" {
			fmt.Printf(": %s", displayText(check.Message))
		}
		fmt.Println()
	}
}

func printFindingChanges(changes *review.FindingChanges) {
	if changes != nil {
		fmt.Printf("Finding changes: %d new, %d resolved, %d unchanged\n", len(changes.New), len(changes.Resolved), changes.Existing)
	}
}

type auditOptions struct {
	IncludeIgnored bool
	WithTools      bool
	MaxFiles       int
	MaxBytes       int64
	Profile        string
	Only           []string
	Skip           []string
	FailOn         string
	Format         string
	Baseline       string
	WriteBaseline  string
}

func defaultAuditOptions() auditOptions {
	return auditOptions{MaxFiles: 10000, MaxBytes: 128 << 20, Profile: "fast", Format: "text"}
}

func parseReviewProfile(args []string) (string, error) {
	options, err := parseReviewOptions(args)
	return options.Profile, err
}

func parseAuditOptions(args []string) (auditOptions, error) {
	options := defaultAuditOptions()
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--include-ignored":
			options.IncludeIgnored = true
		case arg == "--baseline" || arg == "--write-baseline":
			if i+1 >= len(args) {
				return auditOptions{}, fmt.Errorf("%s requires a file path", arg)
			}
			i++
			if arg == "--baseline" {
				options.Baseline = args[i]
			} else {
				options.WriteBaseline = args[i]
			}
		case arg == "--only" || arg == "--skip" || arg == "--fail-on" || arg == "--format":
			if i+1 >= len(args) {
				return auditOptions{}, fmt.Errorf("%s requires a value", arg)
			}
			i++
			v := args[i]
			switch arg {
			case "--only":
				options.Only = splitRuleList(v)
			case "--skip":
				options.Skip = splitRuleList(v)
			case "--fail-on":
				if !validSeverityName(v) {
					return auditOptions{}, fmt.Errorf("invalid --fail-on %q", v)
				}
				options.FailOn = v
			case "--format":
				if v != "text" && v != "sarif" && v != "github" && v != "json" && v != "junit" && v != "codeclimate" {
					return auditOptions{}, fmt.Errorf("invalid --format %q", v)
				}
				options.Format = v
			}
		case arg == "--with-tools":
			options.WithTools = true
		case arg == "--profile":
			if i+1 >= len(args) {
				return auditOptions{}, fmt.Errorf("--profile requires fast or full")
			}
			i++
			if args[i] != "fast" && args[i] != "full" {
				return auditOptions{}, fmt.Errorf("invalid profile %q; expected fast or full", args[i])
			}
			options.Profile = args[i]
		case arg == "--max-files" || arg == "--max-bytes":
			if i+1 >= len(args) {
				return auditOptions{}, fmt.Errorf("%s requires a positive integer", arg)
			}
			i++
			value, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil || value <= 0 {
				return auditOptions{}, fmt.Errorf("%s requires a positive integer", arg)
			}
			if arg == "--max-files" {
				options.MaxFiles = int(value)
			} else {
				options.MaxBytes = value
			}
		case strings.HasPrefix(arg, "--profile="):
			_, profile, _ := strings.Cut(arg, "=")
			if profile != "fast" && profile != "full" {
				return auditOptions{}, fmt.Errorf("invalid profile %q; expected fast or full", profile)
			}
			options.Profile = profile
		case strings.HasPrefix(arg, "--max-files=") || strings.HasPrefix(arg, "--max-bytes="):
			name, raw, _ := strings.Cut(arg, "=")
			value, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || value <= 0 {
				return auditOptions{}, fmt.Errorf("%s requires a positive integer", name)
			}
			if name == "--max-files" {
				options.MaxFiles = int(value)
			} else {
				options.MaxBytes = value
			}
		default:
			return auditOptions{}, fmt.Errorf("unknown audit option %q; usage: m3tal-review audit [--include-ignored] [--max-files N] [--max-bytes N] [--profile fast|full] [--with-tools] [--only rules] [--skip rules] [--fail-on severity] [--format text|sarif|github|json|junit|codeclimate] [--baseline file] [--write-baseline file]", arg)
		}
	}
	return options, nil
}

func workingTreeSnapshot(repositoryRoot string) (string, []string, []string, error) {
	return workingTreeSnapshotWithOptions(repositoryRoot, defaultAuditOptions())
}

func workingTreeSnapshotWithOptions(repositoryRoot string, options auditOptions) (string, []string, []string, error) {
	var diff strings.Builder
	files, unanalyzed, err := walkWorkingTree(repositoryRoot, options, func(_ string, fileDiff string) {
		diff.WriteString(fileDiff)
	})
	if err != nil {
		return "", nil, nil, err
	}
	return diff.String(), files, unanalyzed, nil
}

func walkWorkingTree(repositoryRoot string, options auditOptions, visit func(string, string)) ([]string, []string, error) {
	files, err := git.WorkingTreeFilesWithIgnored(repositoryRoot, options.IncludeIgnored)
	if err != nil {
		return nil, nil, err
	}
	fileSet := make(map[string]bool, len(files))
	unanalyzedSet := make(map[string]bool)
	filesRead := 0
	bytesRead := int64(0)
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
		filesRead++
		if filesRead > options.MaxFiles {
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
		// Stat and read the already-resolved target rather than fullPath so a
		// symlink swapped after EvalSymlinks cannot redirect the read outside
		// the repository.
		contentInfo, contentStatErr := os.Stat(target)
		if contentStatErr != nil {
			unanalyzedSet[file] = true
			fileSet[file] = true
			continue
		}
		if contentInfo.Size() < 0 || contentInfo.Size() > options.MaxBytes-bytesRead {
			unanalyzedSet[file] = true
			fileSet[file] = true
			continue
		}
		content, readErr := os.ReadFile(target)
		fileSet[file] = true
		if readErr != nil || !contentInfo.Mode().IsRegular() || strings.IndexByte(string(content), 0) >= 0 {
			unanalyzedSet[file] = true
			continue
		}
		bytesRead += int64(len(content))
		if (language.CodeChecker{}).Language(file) == language.LanguageUnknown && language.IsLikelySourceFile(file) {
			unanalyzedSet[file] = true
			continue
		}
		visit(file, untrackedFileDiff(file, content, contentInfo.Mode()))
	}
	unanalyzed := make([]string, 0, len(unanalyzedSet))
	for file := range unanalyzedSet {
		unanalyzed = append(unanalyzed, file)
	}
	sort.Strings(unanalyzed)
	return sortedKeys(fileSet), unanalyzed, nil
}

func analyzeWorkingTree(repositoryRoot string, options auditOptions, rules []review.Rule) ([]review.Finding, []string, []string, string, error) {
	var fileRules, policyRules []review.Rule
	for _, rule := range rules {
		switch rule.(type) {
		case review.RiskRule:
			// Risk path signals apply to changed paths; a full audit is a repository inventory.
		case review.PolicyRule:
			policyRules = append(policyRules, rule)
		default:
			fileRules = append(fileRules, rule)
		}
	}
	engine := review.NewEngine(fileRules...)
	hash := sha256.New()
	var findings []review.Finding
	files, unanalyzed, err := walkWorkingTree(repositoryRoot, options, func(_ string, fileDiff string) {
		_, _ = hash.Write([]byte(fileDiff))
		fileFindings := engine.Run(fileDiff)
		findings = append(findings, review.ApplyFindingFilters(fileDiff, fileFindings, repositoryRoot, true)...)
	})
	if err != nil {
		return nil, nil, nil, "", err
	}
	if len(policyRules) > 0 {
		findings = append(findings, review.NewEngine(policyRules...).Run(pathsOnlyDiff(files))...)
	}
	return findings, files, unanalyzed, hex.EncodeToString(hash.Sum(nil)), nil
}

func pathsOnlyDiff(files []string) string {
	var diff strings.Builder
	for _, file := range files {
		fmt.Fprintf(&diff, "diff --git %s %s\n", strconv.Quote("a/"+file), strconv.Quote("b/"+file))
	}
	return diff.String()
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

func diffHash(diff string) string {
	hash := sha256.Sum256([]byte(diff))
	return hex.EncodeToString(hash[:])
}

func attachFindingChanges(repositoryRoot, historyPath string, current *review.Report) {
	entries, err := review.ReadHistory(historyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: unable to compare with prior reviews: %s\n", displayText(err.Error()))
		return
	}
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if entry.Scope != current.Scope || !review.IsValidRunID(entry.RunID) {
			continue
		}
		previousPath := filepath.Join(repositoryRoot, ".m3tal-review", "reports", entry.RunID+".json")
		if err := ensureReviewStorageSafe(repositoryRoot, previousPath); err != nil {
			continue
		}
		previous, err := review.ReadReport(previousPath)
		if err != nil || previous.Branch != current.Branch || normalizedProfile(previous.Profile) != normalizedProfile(current.Profile) {
			continue
		}
		changes := review.CompareFindings(previous.Findings, current.Findings)
		current.FindingChanges = &changes
		return
	}
}

func normalizedProfile(profile string) string {
	if profile == "" {
		return "fast"
	}
	return profile
}

// ensureReviewStorageSafe rejects symlinks in repository-local report and
// history paths. The CLI processes untrusted repositories, so storage paths
// must not redirect writes or reads outside the repository.
func ensureReviewStorageSafe(repositoryRoot string, paths ...string) error {
	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	for _, target := range paths {
		absTarget, err := filepath.Abs(target)
		if err != nil {
			return fmt.Errorf("resolve review storage path: %w", err)
		}
		rel, err := filepath.Rel(root, absTarget)
		if err != nil || !filepath.IsLocal(rel) {
			return fmt.Errorf("review storage path is outside the repository: %s", displayText(target))
		}
		current := root
		parts := strings.Split(rel, string(filepath.Separator))
		for i, part := range parts {
			current = filepath.Join(current, part)
			info, err := os.Lstat(current)
			if os.IsNotExist(err) {
				break
			}
			if err != nil {
				return fmt.Errorf("inspect review storage path %s: %w", displayText(current), err)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing symlink in review storage path: %s", displayText(current))
			}
			if i < len(parts)-1 && !info.IsDir() {
				return fmt.Errorf("review storage path component is not a directory: %s", displayText(current))
			}
		}
	}
	return nil
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
	fmt.Println("    --profile fast|full  Add local Go format, vet, and test checks in full mode")
	fmt.Println("    --with-tools        Run installed gitleaks, gosec, and osv-scanner binaries")
	fmt.Println("  audit")
	fmt.Println("    --profile fast|full  Add local Go format, vet, and test checks in full mode")
	fmt.Println("    --with-tools        Run installed gitleaks, gosec, and osv-scanner binaries")
	fmt.Println("    --include-ignored  Include ignored untracked files (bounded by scan limits)")
	fmt.Println("    --max-files N      Set the maximum files to read (default 10000)")
	fmt.Println("    --max-bytes N      Set the maximum total bytes to read (default 134217728)")
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
