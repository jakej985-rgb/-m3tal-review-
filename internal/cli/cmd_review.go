package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

func runCheckCommand() error {
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
}

func runReviewCommand(commandArgs []string) error {
	for _, arg := range commandArgs {
		if arg == "--pr-mode" {
			return runPRReview(commandArgs)
		}
	}
	options, err := parseReviewOptions(commandArgs)
	if err != nil {
		return err
	}
	cfg, cfgErr := loadUserConfig()
	if cfgErr != nil {
		return cfgErr
	}
	if err := applyUserConfig(&options, cfg); err != nil {
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
	initLanguageOverrides(repositoryRoot)

	branch, err := git.CurrentBranch(repositoryRoot)
	if err != nil {
		return err
	}

	progressEnabled := IsProgressEnabled(options.Progress, options.Format, stdoutIsTTY())
	progress := NewProgressTracker(nil, progressEnabled)
	progress.Stage(1, 4, "Inspecting repository changes")

	var diff string
	var stagedFiles, unanalyzedFiles []string
	var stagedStatuses map[string]string
	var modeChangedFiles, submoduleCandidates func() ([]string, error)
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
		stagedStatuses, err = git.ChangedFileStatusesAgainst(repositoryRoot, options.Base)
		if err != nil {
			return err
		}
		modeChangedFiles = func() ([]string, error) {
			return git.ModeChangedFilesAgainst(repositoryRoot, options.Base)
		}
		submoduleCandidates = func() ([]string, error) {
			return git.SubmoduleFilesAmong(repositoryRoot, stagedFiles)
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
		stagedStatuses, err = git.UnstagedFileStatuses(repositoryRoot)
		if err != nil {
			return err
		}
		unanalyzedFiles, err = git.UnstagedBinaryFiles(repositoryRoot)
		if err != nil {
			return err
		}
		modeChangedFiles = func() ([]string, error) {
			return git.UnstagedModeChangedFiles(repositoryRoot)
		}
		submoduleCandidates = func() ([]string, error) {
			return git.SubmoduleFilesAmong(repositoryRoot, stagedFiles)
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
		modeChangedFiles = func() ([]string, error) {
			return git.StagedModeChangedFiles(repositoryRoot)
		}
		submoduleCandidates = func() ([]string, error) {
			return git.StagedSubmoduleFiles(repositoryRoot)
		}
	}

	if diff == "" {
		fmt.Println("No staged changes to review.")
		return nil
	}
	if int64(len(diff)) > options.MaxDiffSize {
		return fmt.Errorf("diff exceeds --max-diff-size (%d bytes); re-run with a larger limit or review a smaller change set", options.MaxDiffSize)
	}

	// Unanalyzed-file enrichment applies to every review mode:
	// unknown-language sources, submodules, and mode-only changes
	// are review gaps regardless of which diff produced the file set.
	for file, status := range stagedStatuses {
		if status != "D" && (language.CodeChecker{}).Language(file) == language.LanguageUnknown && language.IsLikelySourceFile(file) {
			unanalyzedFiles = append(unanalyzedFiles, file)
		}
	}
	submoduleFiles, err := submoduleCandidates()
	if err != nil {
		return err
	}
	unanalyzedFiles = append(unanalyzedFiles, submoduleFiles...)
	modeChanged, err := modeChangedFiles()
	if err != nil {
		return err
	}
	seenUnanalyzed := make(map[string]bool, len(unanalyzedFiles))
	for _, file := range unanalyzedFiles {
		seenUnanalyzed[file] = true
	}
	for _, file := range modeChanged {
		if !seenUnanalyzed[file] {
			unanalyzedFiles = append(unanalyzedFiles, file)
			seenUnanalyzed[file] = true
		}
	}

	runID, err := review.NewRunID()
	if err != nil {
		return err
	}

	rules, frameworkChecks, err := loadCLIRules(repositoryRoot, options.Degraded, diff, options.Framework, options.RulesFile)
	if err != nil {
		return err
	}

	if options.Base != "" {
		rules = workingTreeRules(rules)
	}
	rules = filterRules(rules, options.Only, options.Skip)
	capProcessCPU(options.Jobs)
	var appFindings []review.Finding
	var appUnanalyzed []string
	var appChecks []review.CheckResult
	var appRuns []review.AppRun
	legacyDiff := diff
	if shouldRunApps(repositoryRoot, options) {
		var routed map[string]bool
		var appErr error
		appFindings, appUnanalyzed, appChecks, appRuns, routed, appErr = runAppsForReview(repositoryRoot, options, stagedFiles, stagedStatuses)
		if appErr != nil {
			return appErr
		}
		legacyDiff = stripRoutedFilesFromDiff(diff, routed)
	}

	progress.Stage(2, 4, "Executing heuristic review rules")
	engine := cappedEngine(options.Jobs, rules...)

	findings := engine.Run(legacyDiff)
	findings = append(findings, appFindings...)
	unanalyzedFiles = append(unanalyzedFiles, appUnanalyzed...)
	frameworkChecks = append(frameworkChecks, appChecks...)

	progress.Stage(3, 4, "Running review pipeline and integrations")

	return RunPipeline(RunnerConfig{
		Scope:                 "staged",
		RepositoryRoot:        repositoryRoot,
		Branch:                branch,
		RunID:                 runID,
		Profile:               options.Profile,
		WithTools:             options.WithTools,
		ToolPaths:             options.ToolPaths,
		Baseline:              options.Baseline,
		WriteBaseline:         options.WriteBaseline,
		Include:               options.Include,
		Exclude:               options.Exclude,
		SortBy:                options.SortBy,
		MaxFindings:           options.MaxFindings,
		Format:                options.Format,
		Snippets:              options.Snippets,
		SummaryOnly:           options.SummaryOnly,
		FailOn:                options.FailOn,
		Version:               version,
		Diff:                  diff,
		StagedFiles:           stagedFiles,
		UnanalyzedFiles:       unanalyzedFiles,
		InitialFindings:       findings,
		WorkingTreeDiff:       options.Base != "",
		Checks:                frameworkChecks,
		Apps:                  appRuns,
		CheckRun:              options.CheckRun,
		CheckRunSHA:           options.CheckRunSHA,
		PRComment:             options.PRComment,
		PluginDir:             reviewPluginDir(options.PluginDir),
		AllowRepoPlugins:      options.AllowRepoPlugins,
		RepoPluginAllowSHA256: cfg.PluginAllowSHA256,
		Semantic:              options.Semantic.pipelineOptions(repositoryRoot),
		Progress:              progress,
	})
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
