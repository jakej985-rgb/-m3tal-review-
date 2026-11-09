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

	"github.com/jakej985-rgb/m3tal-review/internal/deps"
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

	case "check-deps":
		return commandCheckDeps(commandArgs)

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

		rules := defaultRulesWithOptions(repositoryRoot, options.Degraded)
		if options.Base != "" {
			rules = workingTreeRules(rules)
		}
		rules = filterRules(rules, options.Only, options.Skip)
		engine := review.NewEngine(rules...)

		findings := engine.Run(diff)

		return RunPipeline(RunnerConfig{
			Scope:           "staged",
			RepositoryRoot:  repositoryRoot,
			Branch:          branch,
			RunID:           runID,
			Profile:         options.Profile,
			WithTools:       options.WithTools,
			ToolPaths:       options.ToolPaths,
			Baseline:        options.Baseline,
			WriteBaseline:   options.WriteBaseline,
			Include:         options.Include,
			Exclude:         options.Exclude,
			SortBy:          options.SortBy,
			MaxFindings:     options.MaxFindings,
			Format:          options.Format,
			Snippets:        options.Snippets,
			SummaryOnly:     options.SummaryOnly,
			FailOn:          options.FailOn,
			Version:         version,
			Diff:            diff,
			StagedFiles:     stagedFiles,
			UnanalyzedFiles: unanalyzedFiles,
			InitialFindings: findings,
			WorkingTreeDiff: options.Base != "",
			CheckRun:        options.CheckRun,
			CheckRunSHA:     options.CheckRunSHA,
			PRComment:       options.PRComment,
		})

	case "audit":
		options, err := parseAuditOptions(commandArgs)
		if err != nil {
			return err
		}
		cfg, cfgErr := loadUserConfig()
		if cfgErr != nil {
			return cfgErr
		}
		applyUserConfigAudit(&options, cfg)
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
		rules := filterRules(workingTreeRules(defaultRulesWithOptions(repositoryRoot, options.Degraded)), options.Only, options.Skip)
		findings, reviewedFiles, unanalyzedFiles, snapshotHash, coverage, err := analyzeWorkingTree(repositoryRoot, options, rules)
		if err != nil {
			return err
		}
		if options.VulnScan {
			vulnFindings, err := runVulnScan(repositoryRoot)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: vulnerability scan failed: %s\n", displayText(err.Error()))
			} else if vulnFindings != nil {
				if ruleAllowed(options.Only, options.Skip, "dependency-cve") {
					findings = append(findings, vulnFindings...)
				}
			}
		}
		if options.CheckDeps {
			policyConfig, _ := review.ReadLicensePolicyConfig(repositoryRoot, true)
			licensePolicy := deps.LicensePolicy{AllowUnknown: false}
			if policyConfig != nil {
				licensePolicy.Allow = policyConfig.Allow
				licensePolicy.Deny = policyConfig.Deny
				if policyConfig.AllowUnknown != nil {
					licensePolicy.AllowUnknown = *policyConfig.AllowUnknown
				}
			}
			_, depFindings, err := deps.CheckDependencies(repositoryRoot, deps.CheckOptions{LicensePolicy: licensePolicy})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: dependency analysis failed: %s\n", displayText(err.Error()))
			} else {
				for _, df := range depFindings {
					if ruleAllowed(options.Only, options.Skip, df.Rule) {
						findings = append(findings, df)
					}
				}
			}
		}
		return RunPipeline(RunnerConfig{
			Scope:           "working-tree",
			RepositoryRoot:  repositoryRoot,
			Branch:          branch,
			RunID:           runID,
			Profile:         options.Profile,
			WithTools:       options.WithTools,
			ToolPaths:       options.ToolPaths,
			Baseline:        options.Baseline,
			WriteBaseline:   options.WriteBaseline,
			Include:         options.Include,
			Exclude:         options.Exclude,
			Format:          options.Format,
			Snippets:        options.Snippets,
			FailOn:          options.FailOn,
			Version:         version,
			ReviewedFiles:   reviewedFiles,
			UnanalyzedFiles: unanalyzedFiles,
			InitialFindings: findings,
			SnapshotHash:    snapshotHash,
			Coverage:        coverage,
			MaxFiles:        options.MaxFiles,
			MaxBytes:        options.MaxBytes,
			IncludeIgnored:  options.IncludeIgnored,
		})

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

		if len(commandArgs) >= 1 && commandArgs[0] == "prune" {
			return commandHistoryPrune(repositoryRoot, commandArgs[1:])
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
			rest := commandArgs[1:]
			if runID == "show" {
				if len(rest) < 1 {
					return fmt.Errorf("usage: m3tal-review history show <run-id> [--format json]")
				}
				runID = rest[0]
				rest = rest[1:]
			}
			format := "text"
			for i := 0; i < len(rest); i++ {
				if rest[i] == "--format" {
					if i+1 >= len(rest) || (rest[i+1] != "json" && rest[i+1] != "jsonl" && rest[i+1] != "html") {
						return fmt.Errorf("usage: m3tal-review history show <run-id> [--format json|jsonl|html]")
					}
					format = rest[i+1]
				}
			}
			return commandHistoryShowFormat(repositoryRoot, runID, format)
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

	case "repair":
		return commandRepair(commandArgs)

	case "validate-report":
		return runValidateReport(commandArgs)

	case "suppressions", "suppression":
		return runSuppressionsCommand(commandArgs)

	case "config":
		return runConfigCommand(commandArgs)

	case "policy":
		return runPolicyCommand(commandArgs)

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
		review.EntropyRule{RepositoryRoot: repositoryRoot},
		review.TraversalRule{RepositoryRoot: repositoryRoot},
		review.CryptoRule{RepositoryRoot: repositoryRoot},
		review.DeserializationRule{RepositoryRoot: repositoryRoot},
		review.EvalRule{RepositoryRoot: repositoryRoot},
		review.XSSRule{RepositoryRoot: repositoryRoot},
		review.SQLiRule{RepositoryRoot: repositoryRoot},
	}
	return append(rules, review.ExtraRules(repositoryRoot)...)
}

func defaultRulesWithOptions(repositoryRoot string, degraded bool) []review.Rule {
	rules := defaultRules(repositoryRoot)
	if degraded {
		for i, r := range rules {
			if slopRule, ok := r.(review.SlopRule); ok {
				slopRule.Degraded = true
				rules[i] = slopRule
			}
		}
	}
	return rules
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
	ToolPaths      map[string]string
	Degraded       bool
	MaxFiles       int
	MaxBytes       int64
	Profile        string
	Only           []string
	Skip           []string
	Include        []string
	Exclude        []string
	FailOn         string
	Format         string
	Snippets       bool
	Baseline       string
	WriteBaseline  string
	VulnScan       bool
	CheckDeps      bool
	seen           map[string]bool
}

func defaultAuditOptions() auditOptions {
	return auditOptions{
		MaxFiles:  10000,
		MaxBytes:  128 << 20,
		Profile:   "fast",
		Format:    "text",
		ToolPaths: make(map[string]string),
		seen:      map[string]bool{},
	}
}

func parseAuditOptions(args []string) (auditOptions, error) {
	options := defaultAuditOptions()
	for i := 0; i < len(args); i++ {
		arg := args[i]
		flag := arg
		if idx := strings.Index(flag, "="); idx > 0 {
			flag = flag[:idx]
		}
		options.seen[flag] = true
		switch {
		case arg == "--include-ignored":
			options.IncludeIgnored = true
		case arg == "--include" || arg == "--exclude":
			if i+1 >= len(args) {
				return auditOptions{}, fmt.Errorf("%s requires a value", arg)
			}
			i++
			if arg == "--include" {
				options.Include = splitRuleList(args[i])
			} else {
				options.Exclude = splitRuleList(args[i])
			}
		case strings.HasPrefix(arg, "--include="):
			_, v, _ := strings.Cut(arg, "=")
			options.Include = splitRuleList(v)
		case strings.HasPrefix(arg, "--exclude="):
			_, v, _ := strings.Cut(arg, "=")
			options.Exclude = splitRuleList(v)
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
				if v != "text" && v != "sarif" && v != "github" && v != "json" && v != "junit" && v != "codeclimate" && v != "jsonl" && v != "html" {
					return auditOptions{}, fmt.Errorf("invalid --format %q", v)
				}
				options.Format = v
			}
		case arg == "--snippets":
			options.Snippets = true
		case arg == "--with-tools":
			options.WithTools = true
		case arg == "--vuln-scan":
			options.VulnScan = true
		case arg == "--check-deps":
			options.CheckDeps = true
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
		case arg == "--degraded" || arg == "--allow-degraded":
			options.Degraded = true
		case arg == "--tool-path":
			if i+1 >= len(args) {
				return auditOptions{}, fmt.Errorf("%s requires a value", arg)
			}
			i++
			parts := strings.SplitN(args[i], "=", 2)
			if len(parts) == 2 {
				options.ToolPaths[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		case arg == "--gitleaks-path" || arg == "--gosec-path" || arg == "--osv-scanner-path":
			if i+1 >= len(args) {
				return auditOptions{}, fmt.Errorf("%s requires a path", arg)
			}
			i++
			toolName := strings.TrimSuffix(strings.TrimPrefix(arg, "--"), "-path")
			options.ToolPaths[toolName] = args[i]
		default:
			if strings.HasPrefix(arg, "--tool-path=") {
				v := strings.TrimPrefix(arg, "--tool-path=")
				parts := strings.SplitN(v, "=", 2)
				if len(parts) == 2 {
					options.ToolPaths[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
				break
			}
			if strings.HasPrefix(arg, "--gitleaks-path=") {
				options.ToolPaths["gitleaks"] = strings.TrimPrefix(arg, "--gitleaks-path=")
				break
			}
			if strings.HasPrefix(arg, "--gosec-path=") {
				options.ToolPaths["gosec"] = strings.TrimPrefix(arg, "--gosec-path=")
				break
			}
			if strings.HasPrefix(arg, "--osv-scanner-path=") {
				options.ToolPaths["osv-scanner"] = strings.TrimPrefix(arg, "--osv-scanner-path=")
				break
			}
			return auditOptions{}, fmt.Errorf("unknown audit option %q; usage: m3tal-review audit [--include-ignored] [--max-files N] [--max-bytes N] [--profile fast|full] [--with-tools] [--vuln-scan] [--only rules] [--skip rules] [--fail-on severity] [--format text|sarif|github|json|junit|codeclimate|jsonl|html] [--snippets] [--baseline file] [--write-baseline file]", arg)
		}
	}
	return options, nil
}

func workingTreeSnapshotWithOptions(repositoryRoot string, options auditOptions) (string, []string, []string, error) {
	var diff strings.Builder
	files, unanalyzed, _, err := walkWorkingTree(repositoryRoot, options, func(_ string, fileDiff string) {
		diff.WriteString(fileDiff)
	})
	if err != nil {
		return "", nil, nil, err
	}
	return diff.String(), files, unanalyzed, nil
}

func walkWorkingTree(repositoryRoot string, options auditOptions, visit func(string, string)) ([]string, []string, *review.CoverageMetadata, error) {
	files, err := git.WorkingTreeFilesWithIgnored(repositoryRoot, options.IncludeIgnored)
	if err != nil {
		return nil, nil, nil, err
	}
	fileSet := make(map[string]bool, len(files))
	unanalyzedSet := make(map[string]bool)
	var vendorFiles []string
	filesRead := 0
	bytesRead := int64(0)
	for _, file := range files {
		if file == ".m3tal-review" || strings.HasPrefix(file, ".m3tal-review/") || file == ".git" || strings.HasPrefix(file, ".git/") {
			continue
		}
		if review.IsVendorOrDependencyPath(file) && (len(options.Include) == 0 || !pathMatchesAny(options.Include, file)) {
			vendorFiles = append(vendorFiles, file)
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

	cov := &review.CoverageMetadata{
		TotalFiles:      len(files),
		FirstPartyFiles: len(fileSet),
		VendorFiles:     len(vendorFiles),
		UnanalyzedFiles: len(unanalyzed),
	}
	if len(vendorFiles) > 0 {
		cov.Exclusions = append(cov.Exclusions, review.ScopeExclusion{
			Reason: "third-party dependency / vendor path (node_modules, vendor)",
			Count:  len(vendorFiles),
			Paths:  vendorFiles,
		})
	}

	return sortedKeys(fileSet), unanalyzed, cov, nil
}

func analyzeWorkingTree(repositoryRoot string, options auditOptions, rules []review.Rule) ([]review.Finding, []string, []string, string, *review.CoverageMetadata, error) {
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
	cache := newAuditCache(repositoryRoot, fileRules, true)
	defer cache.flush()
	hash := sha256.New()
	var findings []review.Finding
	files, unanalyzed, cov, err := walkWorkingTree(repositoryRoot, options, func(_ string, fileDiff string) {
		_, _ = hash.Write([]byte(fileDiff))
		fileFindings, ok := cache.get(fileDiff)
		if !ok {
			fileFindings = engine.Run(fileDiff)
			cache.put(fileDiff, fileFindings)
		}
		findings = append(findings, review.ApplyFindingFilters(fileDiff, fileFindings, repositoryRoot, true)...)
	})
	if err != nil {
		return nil, nil, nil, "", nil, err
	}
	if len(policyRules) > 0 {
		findings = append(findings, review.NewEngine(policyRules...).Run(pathsOnlyDiff(files))...)
	}
	return findings, files, unanalyzed, hex.EncodeToString(hash.Sum(nil)), cov, nil
}

func pathsOnlyDiff(files []string) string {
	var diff strings.Builder
	for _, file := range files {
		fmt.Fprintf(&diff, "diff --git %s %s\n", strconv.Quote("a/"+file), strconv.Quote("b/"+file))
	}
	return diff.String()
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
	fmt.Println("    --check-run        Post a GitHub Check Run with annotations")
	fmt.Println("    --pr-comment       Comment findings on the current PR via gh")
	fmt.Println("  check-deps [path]   Analyze Go module hygiene and license policy")
	fmt.Println("    --format text|json|jsonl")
	fmt.Println("    --strict          Fail on any hygiene or license finding")
	fmt.Println("    --allow-licenses  Allowlist of approved SPDX licenses")
	fmt.Println("    --deny-licenses   Denylist of forbidden SPDX licenses")
	fmt.Println("    --allow-unknown   Permit unknown/missing dependency licenses")
	fmt.Println("  audit")
	fmt.Println("    --profile fast|full  Add local Go format, vet, and test checks in full mode")
	fmt.Println("    --with-tools        Run installed gitleaks, gosec, and osv-scanner binaries")
	fmt.Println("    --vuln-scan        Query OSV for known CVEs in manifests (network)")
	fmt.Println("    --check-deps       Run Go module hygiene and license policy checks")
	fmt.Println("    --include-ignored  Include ignored untracked files (bounded by scan limits)")
	fmt.Println("    --max-files N      Set the maximum files to read (default 10000)")
	fmt.Println("    --max-bytes N      Set the maximum total bytes to read (default 134217728)")
	fmt.Println("  history [--last N] [--status S] [--scope S] [--grep text] [--format json]")
	fmt.Println("  history show <run-id> [--format json|jsonl|html]")
	fmt.Println("  history prune [--older-than <duration>] [--keep <count>] [--max-size <bytes/mb>] [--dry-run]")
	fmt.Println("  validate-report <path> [--format json|text]")
	fmt.Println("  suppressions audit [--actor <name>] [--rule <rule>] [--file <path>] [--verify]")
	fmt.Println("  config diff [proposed-file] [--base <path>] [--format json|text]")
	fmt.Println("  policy diff|dry-run [proposed-file] [--format json|text]")
	fmt.Println("  show <run-id>")
	fmt.Println("  diff <file.patch>   Review an arbitrary patch file")
	fmt.Println("  stdin               Review a diff from stdin")
	fmt.Println("  watch               Re-review when the staged diff changes")
	fmt.Println("  doctor              Check git/repo/storage health")
	fmt.Println("  list-rules          List all registered rules")
	fmt.Println("  explain <rule>      Explain a rule with an example")
	fmt.Println("  install-hook [--force]  Install a pre-commit hook")
	fmt.Println("  completions <bash|zsh|fish>")
	fmt.Println("  lint")
	fmt.Println("  recover-history")
	fmt.Println("  repair [run-id]     Constrained isolated repair workflow")
	fmt.Println("    --finding <id>     Repair specific finding ID")
	fmt.Println("    --rule <rule>      Repair findings from specific rule")
	fmt.Println("    --fixer <name>     Use specific allowlisted fixer")
	fmt.Println("    --max-attempts N   Maximum repair attempts (default 3)")
	fmt.Println("    --dry-run          Simulate and verify in sandbox without applying")
	fmt.Println("    --yes, --approve   Approve verified repairs without prompt")
	fmt.Println("    --history          Display repair audit history")
	fmt.Println("  version [--json]")
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
