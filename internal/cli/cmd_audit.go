package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/apps"
	"github.com/jakej985-rgb/m3tal-review/internal/deps"
	"github.com/jakej985-rgb/m3tal-review/internal/git"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

type auditOptions struct {
	IncludeIgnored   bool
	WithTools        bool
	ToolPaths        map[string]string
	Degraded         bool
	MaxFiles         int
	MaxBytes         int64
	Jobs             int
	Profile          string
	Only             []string
	Skip             []string
	Include          []string
	Exclude          []string
	FailOn           string
	Format           string
	Snippets         bool
	Baseline         string
	WriteBaseline    string
	VulnScan         bool
	CheckDeps        bool
	WithSlop         bool
	Framework        []string
	RulesFile        string
	PluginDir        string
	AllowRepoPlugins bool
	Progress         *bool
	Semantic         semanticCLIOptions
	Apps             bool
	NoApps           bool
	AppPaths         []string
	AppTimeout       time.Duration
	seen             map[string]bool
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
				if v != "text" && v != "sarif" && v != "github" && v != "github-pr" && v != "json" && v != "junit" && v != "codeclimate" && v != "jsonl" && v != "html" {
					return auditOptions{}, fmt.Errorf("invalid --format %q", v)
				}
				options.Format = v
			}
		case arg == "--snippets":
			options.Snippets = true
		case arg == "--progress":
			p := true
			options.Progress = &p
		case arg == "--no-progress":
			p := false
			options.Progress = &p
		case arg == "--with-tools":
			options.WithTools = true
		case arg == "--with-slop":
			options.WithSlop = true
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
		case arg == "--jobs":
			if i+1 >= len(args) {
				return auditOptions{}, fmt.Errorf("--jobs requires a non-negative integer")
			}
			i++
			value, err := parseJobsValue(args[i])
			if err != nil {
				return auditOptions{}, err
			}
			options.Jobs = value
		case strings.HasPrefix(arg, "--jobs="):
			_, raw, _ := strings.Cut(arg, "=")
			value, err := parseJobsValue(raw)
			if err != nil {
				return auditOptions{}, err
			}
			options.Jobs = value
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
		case arg == "--framework":
			if i+1 >= len(args) {
				return auditOptions{}, fmt.Errorf("--framework requires a value")
			}
			i++
			options.Framework = append(options.Framework, splitRuleList(args[i])...)
		case strings.HasPrefix(arg, "--framework="):
			_, v, _ := strings.Cut(arg, "=")
			options.Framework = append(options.Framework, splitRuleList(v)...)
		case arg == "--rules":
			if i+1 >= len(args) {
				return auditOptions{}, fmt.Errorf("--rules requires a path")
			}
			i++
			options.RulesFile = args[i]
		case strings.HasPrefix(arg, "--rules="):
			_, v, _ := strings.Cut(arg, "=")
			options.RulesFile = v
		case arg == "--plugin-dir":
			if i+1 >= len(args) {
				return auditOptions{}, fmt.Errorf("--plugin-dir requires a path")
			}
			i++
			options.PluginDir = args[i]
		case strings.HasPrefix(arg, "--plugin-dir="):
			_, v, _ := strings.Cut(arg, "=")
			options.PluginDir = v
		case arg == "--allow-repo-plugins":
			options.AllowRepoPlugins = true
		case arg == "--apps":
			options.Apps = true
		case arg == "--no-apps":
			options.NoApps = true
		case arg == "--app-path":
			if i+1 >= len(args) {
				return auditOptions{}, fmt.Errorf("--app-path requires a directory")
			}
			i++
			options.AppPaths = append(options.AppPaths, args[i])
		case strings.HasPrefix(arg, "--app-path="):
			_, v, _ := strings.Cut(arg, "=")
			options.AppPaths = append(options.AppPaths, v)
		case arg == "--app-timeout":
			if i+1 >= len(args) {
				return auditOptions{}, fmt.Errorf("--app-timeout requires a duration")
			}
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil || d <= 0 || d > apps.MaxTimeout {
				return auditOptions{}, fmt.Errorf("invalid --app-timeout %q (must be > 0 and <= %s)", args[i], apps.MaxTimeout)
			}
			options.AppTimeout = d
		case strings.HasPrefix(arg, "--app-timeout="):
			_, v, _ := strings.Cut(arg, "=")
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 || d > apps.MaxTimeout {
				return auditOptions{}, fmt.Errorf("invalid --app-timeout %q (must be > 0 and <= %s)", v, apps.MaxTimeout)
			}
			options.AppTimeout = d
		default:
			if strings.HasPrefix(arg, "--semantic") {
				flag := arg
				hasValue := false
				if idx := strings.Index(arg, "="); idx >= 0 {
					flag, hasValue = arg[:idx], true
				}
				next := func() (string, error) {
					if hasValue {
						return arg[strings.Index(arg, "=")+1:], nil
					}
					if i+1 >= len(args) {
						return "", fmt.Errorf("%s requires a value", flag)
					}
					i++
					return args[i], nil
				}
				handled, err := options.Semantic.parseSemanticFlag(flag, next)
				if err != nil {
					return auditOptions{}, err
				}
				if handled {
					break
				}
			}
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
			return auditOptions{}, fmt.Errorf("unknown audit option %q; usage: m3tal-review audit [--include-ignored] [--max-files N] [--max-bytes N] [--jobs N] [--profile fast|full] [--with-tools] [--with-slop] [--vuln-scan] [--only rules] [--skip rules] [--fail-on severity] [--format text|sarif|github|github-pr|json|junit|codeclimate|jsonl|html] [--snippets] [--baseline file] [--write-baseline file]", arg)
		}
	}
	return options, nil
}

func runAuditCommand(commandArgs []string) error {
	options, err := parseAuditOptions(commandArgs)
	if err != nil {
		return err
	}
	cfg, cfgErr := loadUserConfig()
	if cfgErr != nil {
		return cfgErr
	}
	if err := applyUserConfigAudit(&options, cfg); err != nil {
		return err
	}
	// A --jobs cap has to cover the subprocesses the audit shells out to
	// (git, go vet/test under --profile full, --with-tools scanners), not
	// just rule goroutines, or the machine still pins while a child runs.
	capProcessCPU(options.Jobs)
	// Audit defaults to security signal: code-slop volume drowns real
	// findings, so it is skipped unless --with-slop or an explicit
	// --only/--skip selection is given.
	if !options.WithSlop && len(options.Only) == 0 {
		options.Skip = append(options.Skip, "code-slop")
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
	progress.Stage(1, 4, "Analyzing repository working-tree files")

	runID, err := review.NewRunID()
	if err != nil {
		return err
	}
	rules, frameworkChecks, err := loadCLIRules(repositoryRoot, options.Degraded, "", options.Framework, options.RulesFile)
	if err != nil {
		return err
	}

	rules = filterRules(workingTreeRules(rules), options.Only, options.Skip)
	findings, reviewedFiles, unanalyzedFiles, snapshotHash, coverage, err := analyzeWorkingTree(repositoryRoot, options, rules, progress)
	if err != nil {
		return err
	}
	var appRuns []review.AppRun
	appIncomplete := false
	if options.Apps && !options.NoApps {
		var appFindings []review.Finding
		var appUnanalyzed []string
		var appChecks []review.CheckResult
		var appErr error
		appFindings, appUnanalyzed, appChecks, appRuns, appIncomplete, appErr = runAppsForAudit(repositoryRoot, options, reviewedFiles)
		if appErr != nil {
			return appErr
		}
		findings = append(findings, appFindings...)
		unanalyzedFiles = append(unanalyzedFiles, appUnanalyzed...)
		frameworkChecks = append(frameworkChecks, appChecks...)
	}
	if options.VulnScan || options.CheckDeps {
		progress.Stage(2, 4, "Scanning dependencies and vulnerability databases")
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
	progress.Stage(3, 4, "Executing audit pipeline and finalizing report")
	if err := RunPipeline(RunnerConfig{
		Scope:                 "working-tree",
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
		Format:                options.Format,
		Snippets:              options.Snippets,
		FailOn:                options.FailOn,
		Version:               version,
		ReviewedFiles:         reviewedFiles,
		UnanalyzedFiles:       unanalyzedFiles,
		InitialFindings:       findings,
		SnapshotHash:          snapshotHash,
		Coverage:              coverage,
		Checks:                frameworkChecks,
		Apps:                  appRuns,
		MaxFiles:              options.MaxFiles,
		MaxBytes:              options.MaxBytes,
		IncludeIgnored:        options.IncludeIgnored,
		PluginDir:             reviewPluginDir(options.PluginDir),
		AllowRepoPlugins:      options.AllowRepoPlugins,
		RepoPluginAllowSHA256: cfg.PluginAllowSHA256,
		Semantic:              options.Semantic.pipelineOptions(repositoryRoot),
		Progress:              progress,
	}); err != nil {
		return err
	} else if appIncomplete {
		return fmt.Errorf("audit incomplete: one or more language apps failed or are missing")
	}
	return nil
}

func workingTreeSnapshotWithOptions(repositoryRoot string, options auditOptions) (string, []string, []string, error) {
	var diff strings.Builder
	files, unanalyzed, _, err := walkWorkingTree(repositoryRoot, options, nil, func(_ string, fileDiff string) {
		diff.WriteString(fileDiff)
	})
	if err != nil {
		return "", nil, nil, err
	}
	return diff.String(), files, unanalyzed, nil
}

func walkWorkingTree(repositoryRoot string, options auditOptions, progress ProgressReporter, visit func(string, string)) ([]string, []string, *review.CoverageMetadata, error) {
	files, err := git.WorkingTreeFilesWithIgnored(repositoryRoot, options.IncludeIgnored)
	if err != nil {
		return nil, nil, nil, err
	}
	fileSet := make(map[string]bool, len(files))
	unanalyzedSet := make(map[string]bool)
	var vendorFiles []string
	var dataFiles []string
	const maxSingleAuditFileBytes = 2 << 20 // 2 MB per file limit for working-tree line-by-line analysis
	// EvalSymlinks resolves the final path of each file; the repository root
	// must be canonicalized the same way or Rel fails when the root itself
	// contains a symlink (e.g. /var -> /private/var, 8.3 short names).
	resolvedRoot, rootErr := filepath.EvalSymlinks(repositoryRoot)
	if rootErr != nil {
		resolvedRoot = repositoryRoot
	}
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
		if review.IsDataOrDatasetPath(file) && (len(options.Include) == 0 || !pathMatchesAny(options.Include, file)) {
			dataFiles = append(dataFiles, file)
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
		if progress != nil {
			progress.FileTick(filesRead, len(files), file)
		}
		if filesRead > options.MaxFiles {
			unanalyzedSet[file] = true
			fileSet[file] = true
			continue
		}
		target, evalErr := filepath.EvalSymlinks(fullPath)
		rel, relErr := filepath.Rel(resolvedRoot, target)
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
		if contentInfo.Size() < 0 || contentInfo.Size() > options.MaxBytes-bytesRead || (contentInfo.Size() > maxSingleAuditFileBytes && (len(options.Include) == 0 || !pathMatchesAny(options.Include, file))) {
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
		Complete:        len(unanalyzed) == 0,
	}
	if len(vendorFiles) > 0 {
		cov.Exclusions = append(cov.Exclusions, review.ScopeExclusion{
			Reason: "third-party dependency / vendor path (node_modules, vendor)",
			Count:  len(vendorFiles),
			Paths:  vendorFiles,
		})
	}
	if len(dataFiles) > 0 {
		cov.Exclusions = append(cov.Exclusions, review.ScopeExclusion{
			Reason: "raw dataset / non-code data format (.jsonl, .csv, .parquet, weights, etc.)",
			Count:  len(dataFiles),
			Paths:  dataFiles,
		})
	}

	return sortedKeys(fileSet), unanalyzed, cov, nil
}

func analyzeWorkingTree(repositoryRoot string, options auditOptions, rules []review.Rule, progress ProgressReporter) ([]review.Finding, []string, []string, string, *review.CoverageMetadata, error) {
	var fileRules, policyRules, taintRules []review.Rule
	for _, rule := range rules {
		switch rule.(type) {
		case review.RiskRule:
			// Risk path signals apply to changed paths; a full audit is a repository inventory.
		case review.PolicyRule:
			policyRules = append(policyRules, rule)
		case review.TaintRule:
			// TaintRule performs package-scoped analysis: request/RPC inputs
			// propagate through intra-package calls, so it must see all Go
			// files in a directory together rather than one file per Check.
			taintRules = append(taintRules, rule)
		default:
			fileRules = append(fileRules, rule)
		}
	}
	engine := cappedEngine(options.Jobs, fileRules...)
	salt := ""
	if options.Apps && !options.NoApps {
		salt = appCacheSalt(repositoryRoot, options.AppPaths)
	}
	cache := newAuditCacheWithSalt(repositoryRoot, fileRules, salt, true)
	defer cache.flush()
	hash := sha256.New()
	var findings []review.Finding
	goGroups := make(map[string][]string)
	var goDirs []string
	files, unanalyzed, cov, err := walkWorkingTree(repositoryRoot, options, progress, func(filePath, fileDiff string) {
		_, _ = hash.Write([]byte(fileDiff))
		fileFindings, ok := cache.get(fileDiff)
		if !ok {
			fileFindings = engine.Run(fileDiff)
			cache.put(fileDiff, fileFindings)
		}
		findings = append(findings, review.ApplyFindingFilters(fileDiff, fileFindings, repositoryRoot, true)...)
		if len(taintRules) > 0 && strings.HasSuffix(filePath, ".go") {
			dir := path.Dir(filePath)
			if _, ok := goGroups[dir]; !ok {
				goDirs = append(goDirs, dir)
			}
			goGroups[dir] = append(goGroups[dir], fileDiff)
		}
	})
	if err != nil {
		return nil, nil, nil, "", nil, err
	}
	for _, dir := range goDirs {
		combined := strings.Join(goGroups[dir], "")
		for _, tr := range taintRules {
			// Route through the safe runner: TaintRule.Check alone has
			// no timeout or panic recovery (previously a hung or
			// panicking taint rule could stall/crash the audit).
			taintFindings := review.RunRuleSafely(tr, combined)
			findings = append(findings, review.ApplyFindingFilters(combined, taintFindings, repositoryRoot, true)...)
		}
	}
	if len(policyRules) > 0 {
		findings = append(findings, cappedEngine(options.Jobs, policyRules...).Run(pathsOnlyDiff(files))...)
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
