package cli

import (
	"fmt"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

type reviewOptions struct {
	Profile   string
	WithTools bool
	Only      []string
	Skip      []string
	FailOn    string
	Base      string
	Baseline  string
	Format    string
}

func parseReviewOptions(args []string) (reviewOptions, error) {
	options := reviewOptions{Profile: "fast", Format: "text"}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		value := ""
		if idx := strings.Index(arg, "="); idx >= 0 && strings.HasPrefix(arg, "--") {
			arg, value = arg[:idx], arg[idx+1:]
		}
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
		case "--profile":
			v, err := next()
			if err != nil {
				return options, err
			}
			if v != "fast" && v != "full" {
				return options, fmt.Errorf("invalid profile %q; expected fast or full", v)
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
			if v != "text" && v != "sarif" && v != "github" {
				return options, fmt.Errorf("invalid --format %q; expected text, sarif, or github", v)
			}
			options.Format = v
		default:
			return options, fmt.Errorf("unknown review option %q; usage: m3tal-review review [--profile fast|full] [--with-tools] [--only rules] [--skip rules] [--fail-on severity] [--base ref] [--baseline file] [--format text|sarif|github]", arg)
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
		}
	}
	return rules
}
