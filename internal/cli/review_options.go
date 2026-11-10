package cli

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

type reviewOptions struct {
	Profile          string
	WithTools        bool
	ToolPaths        map[string]string
	Degraded         bool
	Only             []string
	Skip             []string
	FailOn           string
	Base             string
	Baseline         string
	Format           string
	Snippets         bool
	WriteBaseline    string
	CheckRun         bool
	CheckRunSHA      string
	PRComment        bool
	Unstaged         bool
	Include          []string
	Exclude          []string
	SortBy           string
	SummaryOnly      bool
	MaxFindings      int
	MaxDiffSize      int64
	Rule             string
	Framework        []string
	RulesFile        string
	PluginDir        string
	AllowRepoPlugins bool
	Progress         *bool
	// seen records which flags were explicitly passed, so user config
	// defaults only fill in flags the user did not set.
	seen map[string]bool
}

func parseReviewOptions(args []string) (reviewOptions, error) {
	options := reviewOptions{
		Profile:     "fast",
		Format:      "text",
		MaxDiffSize: 64 << 20,
		ToolPaths:   make(map[string]string),
		seen:        map[string]bool{},
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		value := ""
		if idx := strings.Index(arg, "="); idx >= 0 && strings.HasPrefix(arg, "--") {
			arg, value = arg[:idx], arg[idx+1:]
		}
		options.seen[arg] = true
		next := func() (string, error) {
			if value != "" {
				return value, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", arg)
			}
			i++
			return args[i], nil
		}
		switch arg {
		case "--with-tools":
			options.WithTools = true
		case "--progress":
			p := true
			options.Progress = &p
		case "--no-progress":
			p := false
			options.Progress = &p
		case "--profile":
			v, err := next()
			if err != nil {
				return options, err
			}
			if v != "fast" && v != "full" && v != "security" && v != "slop" && v != "ci" {
				return options, fmt.Errorf("invalid profile %q; expected fast, full, security, slop, or ci", v)
			}
			options.Profile = v
		case "--only":
			v, err := next()
			if err != nil {
				return options, err
			}
			options.Only = splitRuleList(v)
		case "--skip":
			v, err := next()
			if err != nil {
				return options, err
			}
			options.Skip = splitRuleList(v)
		case "--fail-on":
			v, err := next()
			if err != nil {
				return options, err
			}
			if !validSeverityName(v) {
				return options, fmt.Errorf("invalid --fail-on %q; expected info, low, medium, high, or critical", v)
			}
			options.FailOn = v
		case "--baseline":
			v, err := next()
			if err != nil {
				return options, err
			}
			options.Baseline = v
		case "--unstaged":
			options.Unstaged = true
		case "--check-run":
			options.CheckRun = true
		case "--pr-comment":
			options.PRComment = true
		case "--check-run-sha":
			if i+1 >= len(args) {
				return options, fmt.Errorf("--check-run-sha requires a value")
			}
			i++
			options.CheckRunSHA = args[i]
		case "--write-baseline":
			v, err := next()
			if err != nil {
				return options, err
			}
			options.WriteBaseline = v
		case "--include":
			v, err := next()
			if err != nil {
				return options, err
			}
			options.Include = splitRuleList(v)
		case "--exclude":
			v, err := next()
			if err != nil {
				return options, err
			}
			options.Exclude = splitRuleList(v)
		case "--sort-by":
			v, err := next()
			if err != nil {
				return options, err
			}
			if v != "severity" && v != "file" && v != "rule" {
				return options, fmt.Errorf("invalid --sort-by %q; expected severity, file, or rule", v)
			}
			options.SortBy = v
		case "--summary-only":
			options.SummaryOnly = true
		case "--max-findings":
			v, err := next()
			if err != nil {
				return options, err
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return options, fmt.Errorf("invalid --max-findings %q; expected a positive integer", v)
			}
			options.MaxFindings = n
		case "--max-diff-size":
			v, err := next()
			if err != nil {
				return options, err
			}
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 1 {
				return options, fmt.Errorf("invalid --max-diff-size %q; expected bytes", v)
			}
			options.MaxDiffSize = n
		case "--rule":
			v, err := next()
			if err != nil {
				return options, err
			}
			options.Rule = v
			options.Only = []string{v}
		case "--base":
			v, err := next()
			if err != nil {
				return options, err
			}
			options.Base = v
		case "--format":
			v, err := next()
			if err != nil {
				return options, err
			}
			if v != "text" && v != "sarif" && v != "github" && v != "json" && v != "junit" && v != "codeclimate" && v != "jsonl" && v != "html" {
				return options, fmt.Errorf("invalid --format %q; expected text, sarif, github, json, junit, codeclimate, jsonl, or html", v)
			}
			options.Format = v
		case "--snippets":
			options.Snippets = true
		case "--degraded", "--allow-degraded":
			options.Degraded = true
		case "--tool-path":
			v, err := next()
			if err != nil {
				return options, err
			}
			parts := strings.SplitN(v, "=", 2)
			if len(parts) == 2 {
				options.ToolPaths[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		case "--gitleaks-path":
			v, err := next()
			if err != nil {
				return options, err
			}
			options.ToolPaths["gitleaks"] = v
		case "--gosec-path":
			v, err := next()
			if err != nil {
				return options, err
			}
			options.ToolPaths["gosec"] = v
		case "--osv-scanner-path":
			v, err := next()
			if err != nil {
				return options, err
			}
			options.ToolPaths["osv-scanner"] = v
		case "--framework":
			v, err := next()
			if err != nil {
				return options, err
			}
			options.Framework = append(options.Framework, splitRuleList(v)...)
		case "--rules":
			v, err := next()
			if err != nil {
				return options, err
			}
			options.RulesFile = v
		case "--plugin-dir":
			v, err := next()
			if err != nil {
				return options, err
			}
			options.PluginDir = v
		case "--allow-repo-plugins":
			options.AllowRepoPlugins = true
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
			return options, fmt.Errorf("unknown review option %q; usage: m3tal-review review [--profile fast|full] [--with-tools] [--only rules] [--skip rules] [--fail-on severity] [--base ref] [--baseline file] [--format text|sarif|github|json|junit|codeclimate|jsonl|html] [--snippets]", arg)
		}
	}
	// Profile presets restrict the rule set for common workflows (explicit
	// --only/--rule flags take precedence).
	if len(options.Only) == 0 {
		switch options.Profile {
		case "security":
			options.Only = []string{"hardcoded-credential", "exposed-secret", "secret-file", "secret-material", "ssrf", "command-injection", "open-redirect", "template-injection", "prototype-pollution", "archive-extraction", "xxe", "injection-other", "unsafe-code", "jwt-misuse", "hardcoded-session-secret", "tls-verification", "weak-crypto-params", "timing-unsafe-compare", "insecure-randomness", "insecure-permissions", "cors-misconfig", "cookie-flags", "web-storage-secrets", "postmessage-origin", "xss-extra-sinks", "deserialization-gadgets", "weak-encoding-crypto", "websocket-origin", "path-traversal", "weak-cryptography", "unsafe-deserialization", "dangerous-eval", "cross-site-scripting", "sql-injection", "risky-shell-execution", "world-writable-file-mode", "insecure-tls-verification", "review-risk", "query-token-exposure", "plaintext-secret-storage", "actions-credential-url", "privileged-service-execution", "shell-script-safety"}
		case "slop":
			options.Only = []string{"code-slop"}
		case "ci":
			options.Only = []string{"unpinned-action", "pull-request-target", "actions-script-injection", "pipe-to-shell", "unpinned-image", "ci-secret-exposure", "container-privilege", "dockerfile-remote-add", "dockerfile-user", "secret-file", "secret-material", "actions-credential-url", "workflow-force-push"}
		}
	}
	return options, nil
}

func splitRuleList(value string) []string {
	var names []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			names = append(names, part)
		}
	}
	return names
}

func validSeverityName(s string) bool {
	switch s {
	case "info", "low", "medium", "high", "critical":
		return true
	}
	return false
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// filterRules applies --only/--skip against rule names.
func filterRules(rules []review.Rule, only, skip []string) []review.Rule {
	if len(only) == 0 && len(skip) == 0 {
		return rules
	}
	onlySet := make(map[string]bool, len(only))
	for _, name := range only {
		onlySet[name] = true
	}
	skipSet := make(map[string]bool, len(skip))
	for _, name := range skip {
		skipSet[name] = true
	}
	var out []review.Rule
	for _, rule := range rules {
		name := rule.Name()
		if len(onlySet) > 0 && !onlySet[name] {
			continue
		}
		if skipSet[name] {
			continue
		}
		out = append(out, rule)
	}
	return out
}

// workingTreeRules returns rules configured to read the working tree instead
// of the git index (used by audit and review --base).
func workingTreeRules(rules []review.Rule) []review.Rule {
	for i, rule := range rules {
		if aware, ok := rule.(review.WorkingTreeAware); ok {
			aware.EnableWorkingTree()
			continue
		}
		switch typed := rule.(type) {
		case review.TodoRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.RiskRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.PolicyRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.SlopRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.SecurityRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.ShellRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.TLSRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.PermissionsRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.DebugRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.SecretRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.EntropyRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.TraversalRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.CryptoRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.DeserializationRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.EvalRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.XSSRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.SQLiRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.TaintRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.ScopeDefaultRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.PluginTrustRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.PrivilegedExecRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.ProcessKillRule:
			typed.WorkingTree = true
			rules[i] = typed
		case review.CredentialQueryRule:
			typed.WorkingTree = true
			rules[i] = typed
		}
	}
	return rules
}

// filterFindingsByPath keeps findings whose file matches any --include glob
// and drops those matching any --exclude glob. Empty lists match everything.
func filterFindingsByPath(findings []review.Finding, include, exclude []string) []review.Finding {
	if len(include) == 0 && len(exclude) == 0 {
		return findings
	}
	out := findings[:0]
	for _, f := range findings {
		if len(include) > 0 && !pathMatchesAny(include, f.File) {
			continue
		}
		if len(exclude) > 0 && pathMatchesAny(exclude, f.File) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func pathMatchesAny(globs []string, path string) bool {
	for _, g := range globs {
		if ok, _ := filepath.Match(g, path); ok {
			return true
		}
		if ok, _ := filepath.Match(g, filepath.Base(path)); ok {
			return true
		}
	}
	return false
}

// sortFindings orders findings deterministically by the requested key.
func sortFindings(findings []review.Finding, sortBy string) []review.Finding {
	if sortBy == "" {
		return findings
	}
	sorted := make([]review.Finding, len(findings))
	copy(sorted, findings)
	switch sortBy {
	case "severity":
		sort.SliceStable(sorted, func(i, j int) bool {
			ri, rj := severityRank(sorted[i].Severity), severityRank(sorted[j].Severity)
			if ri != rj {
				return ri > rj
			}
			if sorted[i].File != sorted[j].File {
				return sorted[i].File < sorted[j].File
			}
			return sorted[i].Line < sorted[j].Line
		})
	case "file":
		sort.SliceStable(sorted, func(i, j int) bool {
			if sorted[i].File != sorted[j].File {
				return sorted[i].File < sorted[j].File
			}
			return sorted[i].Line < sorted[j].Line
		})
	case "rule":
		sort.SliceStable(sorted, func(i, j int) bool {
			if sorted[i].Rule != sorted[j].Rule {
				return sorted[i].Rule < sorted[j].Rule
			}
			return sorted[i].File < sorted[j].File
		})
	}
	return sorted
}
