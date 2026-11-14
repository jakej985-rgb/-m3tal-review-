package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis/pipeline"
	"github.com/jakej985-rgb/m3tal-review/internal/git"
	"github.com/jakej985-rgb/m3tal-review/internal/plugin"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// RunnerConfig specifies parameters for review and audit execution pipelines.
type RunnerConfig struct {
	Scope          string // "staged" or "working-tree"
	RepositoryRoot string
	Branch         string
	RunID          string
	Profile        string
	WithTools      bool
	ToolPaths      map[string]string
	Baseline       string
	WriteBaseline  string
	Include        []string
	Exclude        []string
	SortBy         string
	MaxFindings    int
	Format         string
	Snippets       bool
	SummaryOnly    bool
	FailOn         string
	Version        string

	// Inputs
	Diff            string
	StagedFiles     []string
	ReviewedFiles   []string
	UnanalyzedFiles []string
	InitialFindings []review.Finding
	SnapshotHash    string
	Coverage        *review.CoverageMetadata
	WorkingTreeDiff bool
	Checks          []review.CheckResult

	// Review-specific integration flags
	CheckRun    bool
	CheckRunSHA string
	PRComment   bool

	// Audit-specific limits
	MaxFiles       int
	MaxBytes       int64
	IncludeIgnored bool

	// Progress reporting
	Progress ProgressReporter

	// Plugin analyzers
	PluginRegistry   *plugin.Registry
	PluginDir        string
	AllowRepoPlugins bool
	// RepoPluginAllowSHA256 lists SHA-256 hashes (hex) of repository-local
	// plugin executables the user explicitly trusts. Repository plugins are
	// only executed when AllowRepoPlugins is set AND their executable hash is
	// on this list; an empty list loads no repository plugins.
	RepoPluginAllowSHA256 []string

	// Semantic configures the opt-in semantic analysis pipeline
	// (internal/analysis/pipeline). Nil disables it entirely.
	Semantic *pipeline.Options
	// Context optionally carries cancellation/deadline into the
	// semantic pipeline; nil means context.Background().
	Context context.Context
}

// RunPipeline executes the shared review-runner pipeline for both review and audit.
func RunPipeline(cfg RunnerConfig) error {
	findings := make([]review.Finding, len(cfg.InitialFindings))
	copy(findings, cfg.InitialFindings)

	var confidenceChecks []review.CheckResult
	if cfg.Profile == "full" {
		if cfg.Progress != nil {
			cfg.Progress.Tick("Running Go confidence checks")
		}
		checkFindings, results := runGoConfidenceChecks(cfg.RepositoryRoot)
		findings = append(findings, checkFindings...)
		confidenceChecks = results
	}
	if cfg.WithTools {
		if cfg.Progress != nil {
			cfg.Progress.Tick("Running external tool scanners")
		}
		toolFindings, results := runOptionalLocalToolsWithOverrides(cfg.RepositoryRoot, cfg.ToolPaths)
		findings = append(findings, toolFindings...)
		confidenceChecks = append(confidenceChecks, results...)
	}

	// Semantic pipeline: loads the Go program model once and runs the
	// enabled analysis engines over it. Findings are normalized into
	// the shared analysis contract and adapted to the legacy report
	// shape with category "semantic"; per-analyzer outcomes and
	// diagnostics land in report.Analysis.
	var analysisSection *review.AnalysisSection
	if cfg.Semantic != nil {
		if cfg.Progress != nil {
			cfg.Progress.Tick("Running semantic analyzers")
		}
		semFindings, semChecks, section := runSemanticPipeline(cfg)
		findings = append(findings, semFindings...)
		confidenceChecks = append(confidenceChecks, semChecks...)
		analysisSection = section
	}

	// Discover and execute plugin analyzers
	var pluginRegistry *plugin.Registry
	if cfg.PluginRegistry != nil {
		pluginRegistry = cfg.PluginRegistry
	} else {
		pluginDirs := make([]string, 0, 2)
		if cfg.PluginDir != "" {
			pluginDirs = append(pluginDirs, cfg.PluginDir)
		}
		pluginRegistry = discoverPluginRegistry(pluginDirs)
		// Plugins inside the scanned repository are untrusted code: they are
		// only loaded when the user explicitly opts in AND the executable's
		// SHA-256 is on the user's allowlist.
		if cfg.AllowRepoPlugins && cfg.RepositoryRoot != "" {
			repoDir := filepath.Join(cfg.RepositoryRoot, ".m3tal-review", "plugins")
			allowed := make(map[string]bool, len(cfg.RepoPluginAllowSHA256))
			for _, h := range cfg.RepoPluginAllowSHA256 {
				allowed[strings.ToLower(strings.TrimSpace(h))] = true
			}
			// Discovery verifies each executable's hash before any --manifest
			// probe, so unlisted binaries are never executed.
			if discovered, err := plugin.DiscoverPluginsAllowlisted(repoDir, allowed); err == nil && len(discovered) > 0 {
				if pluginRegistry == nil {
					pluginRegistry = plugin.NewRegistry()
				}
				for _, p := range discovered {
					_ = pluginRegistry.Register(p)
				}
			}
		}
	}

	if pluginRegistry != nil && len(pluginRegistry.List()) > 0 {
		if cfg.Progress != nil {
			cfg.Progress.Tick("Running plugin analyzers")
		}
		var targetFiles []string
		if cfg.Scope == "working-tree" {
			targetFiles = cfg.ReviewedFiles
		} else {
			targetFiles = cfg.StagedFiles
		}
		pFindings, pChecks := pluginRegistry.RunPlugins(context.Background(), plugin.PluginInput{
			RepositoryRoot: cfg.RepositoryRoot,
			Scope:          cfg.Scope,
			Files:          targetFiles,
			Diff:           cfg.Diff,
		})
		findings = append(findings, pFindings...)
		confidenceChecks = append(confidenceChecks, pChecks...)
	}

	findings = review.GroupFindings(findings)

	if cfg.Scope == "staged" && cfg.Diff != "" {
		findings = review.ApplyFindingFilters(cfg.Diff, findings, cfg.RepositoryRoot, cfg.WorkingTreeDiff)
	}

	if cfg.Baseline != "" {
		baseline, err := loadBaseline(cfg.Baseline)
		if err != nil {
			return err
		}
		findings = filterBaseline(findings, baseline)
	}

	findings = filterFindingsByPath(findings, cfg.Include, cfg.Exclude)
	findings = sortFindings(findings, cfg.SortBy)
	if cfg.MaxFindings > 0 && len(findings) > cfg.MaxFindings {
		findings = findings[:cfg.MaxFindings]
	}

	if cfg.WriteBaseline != "" {
		if err := writeBaseline(cfg.WriteBaseline, findings); err != nil {
			return err
		}
		fmt.Println("Baseline written:", displayText(cfg.WriteBaseline))
	}

	if cfg.CheckRun {
		if err := postCheckRun(findings, cfg.CheckRunSHA); err != nil {
			return fmt.Errorf("post check run: %w", err)
		}
		fmt.Println("Check run posted.")
	}

	if cfg.PRComment {
		if err := postPRComment(cfg.RepositoryRoot, findings); err != nil {
			return fmt.Errorf("post pr comment: %w", err)
		}
		fmt.Println("PR comment posted.")
	}

	currentSHA, err := git.CurrentCommitSHA(cfg.RepositoryRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: unable to determine current commit SHA: %s\n", displayText(err.Error()))
		currentSHA = "unavailable"
	}

	var files []string
	var diffHashVal string
	if cfg.Scope == "working-tree" {
		files = cfg.ReviewedFiles
		diffHashVal = cfg.SnapshotHash
	} else {
		files = cfg.StagedFiles
		diffHashVal = diffHash(cfg.Diff)
	}

	report := review.NewReport(
		cfg.RunID,
		cfg.RepositoryRoot,
		cfg.Branch,
		currentSHA,
		currentSHA,
		diffHashVal,
		cfg.Version,
		files,
		findings,
	)
	report.Profile = cfg.Profile
	report.Checks = append(report.Checks, confidenceChecks...)
	report.Checks = append(report.Checks, cfg.Checks...)
	report.Scope = cfg.Scope
	report.Coverage = cfg.Coverage
	report.Analysis = analysisSection

	if cfg.Scope == "working-tree" {
		if len(cfg.UnanalyzedFiles) > 0 {
			report.UnanalyzedFiles = cfg.UnanalyzedFiles
			report.Passed = false
			report.Summary = "Audit incomplete. Some working-tree files could not be analyzed."
		} else if !report.Passed {
			report.Summary = "Audit found findings that require attention."
		} else if len(findings) > 0 {
			report.Summary = "Audit passed with informational risk signals."
		}
	} else {
		if len(cfg.UnanalyzedFiles) > 0 {
			report.UnanalyzedFiles = cfg.UnanalyzedFiles
			report.Passed = false
			report.Summary = "Review incomplete. Some staged files could not be analyzed."
		}
	}

	if review.ValidateCommitSHA(currentSHA) == nil {
		hashVal := ""
		if cfg.Scope == "working-tree" {
			hashVal = cfg.SnapshotHash
		}
		if att, err := review.GenerateAttestation(&report, hashVal); err == nil {
			report.Attestation = &att
		}
	}

	isWorkingTree := cfg.Scope == "working-tree"
	diffArg := cfg.Diff
	if isWorkingTree {
		diffArg = ""
	}
	review.AttachSnippetsToReport(&report, diffArg, cfg.RepositoryRoot, isWorkingTree)

	reportPath := filepath.Join(cfg.RepositoryRoot, ".m3tal-review", "reports", cfg.RunID+".json")
	historyPath := filepath.Join(cfg.RepositoryRoot, ".m3tal-review", "history.jsonl")
	if err := ensureReviewStorageSafe(cfg.RepositoryRoot, reportPath, historyPath); err != nil {
		return err
	}

	attachFindingChanges(cfg.RepositoryRoot, historyPath, &report)
	if cfg.Progress != nil {
		cfg.Progress.Tick("Saving report and run history")
	}
	if err := review.WriteReport(reportPath, report); err != nil {
		return err
	}
	if err := review.AppendHistory(historyPath, review.NewHistoryEntry(report)); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to append to history log (report was successfully saved to %s): %s\n", displayText(reportPath), displayText(err.Error()))
	}
	if cfg.Progress != nil {
		cfg.Progress.Done("Analysis pipeline complete")
	}

	fmt.Println(displayText(report.Summary))
	fmt.Println("Scope:", cfg.Scope)
	fmt.Println("Profile:", cfg.Profile)
	printFindingChanges(report.FindingChanges)
	printCheckResults(report.Checks)
	if cfg.Scope == "working-tree" {
		fmt.Printf("Scan limits: %d files, %d bytes; ignored files included: %t\n", cfg.MaxFiles, cfg.MaxBytes, cfg.IncludeIgnored)
	}
	fmt.Println("Security checks are heuristic; see README for coverage and limitations.")
	fmt.Println("Run ID:", displayText(cfg.RunID))
	fmt.Println("Report:", displayText(reportPath))

	if cfg.Scope == "staged" && len(report.UnanalyzedFiles) > 0 {
		fmt.Println("Not fully analyzed (binary, unsupported source language, submodule, or file-mode changes):")
		for _, file := range report.UnanalyzedFiles {
			fmt.Println("  ", displayText(file))
		}
	}

	switch cfg.Format {
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
	case "jsonl":
		out, err := formatFindingsJSONL(report.Findings)
		if err != nil {
			return err
		}
		fmt.Print(out)
	case "html":
		out, err := formatReportHTML(report)
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
		if !cfg.SummaryOnly {
			for _, finding := range report.Findings {
				location := displayText(finding.File)
				if finding.Line > 0 {
					location = fmt.Sprintf("%s:%d", location, finding.Line)
				}
				fmt.Printf("[%s] %s: %s (%s)\n", displayText(finding.Severity), location, displayText(finding.Message), displayText(finding.Rule))
				if finding.Remediation != "" && cfg.Scope == "staged" {
					fmt.Printf("  Remediation: %s\n", displayText(finding.Remediation))
				}
				if cfg.Snippets && finding.Snippet != "" {
					lines := strings.Split(strings.TrimRight(finding.Snippet, "\n"), "\n")
					for _, l := range lines {
						fmt.Printf("  %s\n", displayText(l))
					}
				}
			}
		}
	}

	if cfg.Scope == "working-tree" && len(report.UnanalyzedFiles) > 0 && cfg.FailOn == "" {
		fmt.Println("Unanalyzed files:")
		for _, file := range report.UnanalyzedFiles {
			fmt.Println("  ", displayText(file))
		}
	}

	if cfg.FailOn != "" {
		threshold := severityRank(cfg.FailOn)
		blocking := 0
		for _, finding := range report.Findings {
			if severityRank(finding.Severity) >= threshold {
				blocking++
			}
		}
		if cfg.Scope == "staged" {
			if blocking == 0 && len(report.UnanalyzedFiles) == 0 {
				return nil
			}
			if len(report.UnanalyzedFiles) > 0 {
				return fmt.Errorf("review found %d issue(s) at or above %s and could not analyze %d staged file(s)", blocking, cfg.FailOn, len(report.UnanalyzedFiles))
			}
			return fmt.Errorf("review found %d issue(s) at or above %s", blocking, cfg.FailOn)
		} else {
			if blocking > 0 || len(report.UnanalyzedFiles) > 0 {
				return fmt.Errorf("audit found %d issue(s) at or above %s", blocking, cfg.FailOn)
			}
			return nil
		}
	}

	if !report.Passed {
		if cfg.Scope == "staged" {
			if len(report.UnanalyzedFiles) > 0 && len(report.Findings) == 0 {
				return fmt.Errorf("review incomplete: %d staged file(s) could not be analyzed", len(report.UnanalyzedFiles))
			}
			if len(report.UnanalyzedFiles) > 0 {
				return fmt.Errorf("review found %d issue(s) and could not analyze %d staged file(s)", len(report.Findings), len(report.UnanalyzedFiles))
			}
			return fmt.Errorf("review found %d issue(s)", len(report.Findings))
		} else {
			if len(report.UnanalyzedFiles) > 0 {
				return fmt.Errorf("audit incomplete: %d file(s) could not be analyzed", len(report.UnanalyzedFiles))
			}
			return fmt.Errorf("audit found %d issue(s)", len(report.Findings))
		}
	}

	return nil
}

// discoverPluginRegistry loads plugins from each trusted directory. Earlier
// directories win on name conflicts.
func discoverPluginRegistry(dirs []string) *plugin.Registry {
	var registry *plugin.Registry
	for _, dir := range dirs {
		discovered, err := plugin.DiscoverPlugins(dir)
		if err != nil || len(discovered) == 0 {
			continue
		}
		if registry == nil {
			registry = plugin.NewRegistry()
		}
		for _, p := range discovered {
			_ = registry.Register(p)
		}
	}
	return registry
}
