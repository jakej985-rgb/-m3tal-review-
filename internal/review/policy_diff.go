package review

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"
)

type StringSliceDiff struct {
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

type CouplingDiff struct {
	Added    []PathCoupling         `json:"added,omitempty"`
	Removed  []PathCoupling         `json:"removed,omitempty"`
	Modified []CouplingModifiedDiff `json:"modified,omitempty"`
}

type CouplingModifiedDiff struct {
	WhenChanged    string   `json:"when_changed"`
	BaseAlsoChange []string `json:"base_also_change"`
	PropAlsoChange []string `json:"proposed_also_change"`
}

type RuleTuningDiff struct {
	Added    map[string]PolicyRuleTuning `json:"added,omitempty"`
	Removed  map[string]PolicyRuleTuning `json:"removed,omitempty"`
	Modified map[string]RuleModifiedDiff `json:"modified,omitempty"`
}

type RuleModifiedDiff struct {
	Rule     string           `json:"rule"`
	Base     PolicyRuleTuning `json:"base"`
	Proposed PolicyRuleTuning `json:"proposed"`
}

type PathOverrideDiff struct {
	Added    map[string]map[string]PolicyRuleTuning `json:"added,omitempty"`
	Removed  map[string]map[string]PolicyRuleTuning `json:"removed,omitempty"`
	Modified map[string]RuleTuningDiff              `json:"modified,omitempty"`
}

type PolicyDiffResult struct {
	Valid            bool             `json:"valid"`
	ValidationErrors []string         `json:"validation_errors,omitempty"`
	HasChanges       bool             `json:"has_changes"`
	BasePath         string           `json:"base_path,omitempty"`
	ProposedPath     string           `json:"proposed_path,omitempty"`
	RiskPaths        StringSliceDiff  `json:"risk_paths"`
	ForbiddenPaths   StringSliceDiff  `json:"forbidden_paths"`
	RequireTogether  CouplingDiff     `json:"require_together"`
	Rules            RuleTuningDiff   `json:"rules"`
	Paths            PathOverrideDiff `json:"paths"`
}

// ParseReviewPolicy validates and parses raw JSON policy data.
func ParseReviewPolicy(data []byte) (ReviewPolicy, []string, error) {
	var policy ReviewPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return ReviewPolicy{}, []string{fmt.Sprintf("JSON parse error: %v", err)}, err
	}

	var valErrors []string

	checkPattern := func(field, pattern string) {
		if pattern == "" {
			valErrors = append(valErrors, fmt.Sprintf("%s: empty path pattern is forbidden", field))
			return
		}
		for _, seg := range strings.Split(pattern, "/") {
			if seg == "**" {
				continue
			}
			if _, err := path.Match(seg, "test"); err != nil {
				valErrors = append(valErrors, fmt.Sprintf("%s: invalid glob pattern %q (%v)", field, pattern, err))
			}
		}
	}

	for _, p := range policy.RiskPaths {
		checkPattern("risk_paths", p)
	}

	for _, p := range policy.ForbiddenPaths {
		checkPattern("forbidden_paths", p)
	}

	for i, c := range policy.RequireTogether {
		if strings.TrimSpace(c.WhenChanged) == "" {
			valErrors = append(valErrors, fmt.Sprintf("require_together[%d]: when_changed cannot be empty", i))
		} else {
			checkPattern(fmt.Sprintf("require_together[%d].when_changed", i), c.WhenChanged)
		}

		if len(c.AlsoChange) == 0 {
			valErrors = append(valErrors, fmt.Sprintf("require_together[%d] (%q): also_change list cannot be empty", i, c.WhenChanged))
		} else {
			for j, also := range c.AlsoChange {
				checkPattern(fmt.Sprintf("require_together[%d].also_change[%d]", i, j), also)
			}
		}
	}

	for ruleName, tuning := range policy.Rules {
		if tuning.Severity != "" && !ValidSeverities[tuning.Severity] {
			valErrors = append(valErrors, fmt.Sprintf("rules[%q]: invalid severity %q; valid: info, low, medium, high, critical", ruleName, tuning.Severity))
		}
	}

	for pathGlob, rulesMap := range policy.Paths {
		checkPattern(fmt.Sprintf("paths[%q]", pathGlob), pathGlob)
		for rName, tuning := range rulesMap {
			if tuning.Severity != "" && !ValidSeverities[tuning.Severity] {
				valErrors = append(valErrors, fmt.Sprintf("paths[%q][%q]: invalid severity %q", pathGlob, rName, tuning.Severity))
			}
		}
	}

	return policy, valErrors, nil
}

// ReadReviewPolicyFile reads and validates a policy file from path.
func ReadReviewPolicyFile(filePath string) (ReviewPolicy, []string, error) {
	if info, err := os.Lstat(filePath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return ReviewPolicy{}, []string{"policy file must not be a symbolic link"}, fmt.Errorf("%s must not be a symbolic link", filePath)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return ReviewPolicy{}, nil, nil
		}
		return ReviewPolicy{}, []string{fmt.Sprintf("read error: %v", err)}, err
	}

	return ParseReviewPolicy(data)
}

func diffStringSlices(base, proposed []string) StringSliceDiff {
	baseMap := make(map[string]bool, len(base))
	for _, s := range base {
		baseMap[s] = true
	}
	propMap := make(map[string]bool, len(proposed))
	for _, s := range proposed {
		propMap[s] = true
	}

	var added []string
	for _, s := range proposed {
		if !baseMap[s] {
			added = append(added, s)
		}
	}
	sort.Strings(added)

	var removed []string
	for _, s := range base {
		if !propMap[s] {
			removed = append(removed, s)
		}
	}
	sort.Strings(removed)

	return StringSliceDiff{Added: added, Removed: removed}
}

func diffCouplings(base, proposed []PathCoupling) CouplingDiff {
	var diff CouplingDiff

	baseMap := make(map[string][]string, len(base))
	for _, c := range base {
		baseMap[c.WhenChanged] = c.AlsoChange
	}

	propMap := make(map[string][]string, len(proposed))
	for _, c := range proposed {
		propMap[c.WhenChanged] = c.AlsoChange
	}

	for _, c := range proposed {
		if baseAlso, exists := baseMap[c.WhenChanged]; !exists {
			diff.Added = append(diff.Added, c)
		} else if !reflect.DeepEqual(baseAlso, c.AlsoChange) {
			diff.Modified = append(diff.Modified, CouplingModifiedDiff{
				WhenChanged:    c.WhenChanged,
				BaseAlsoChange: baseAlso,
				PropAlsoChange: c.AlsoChange,
			})
		}
	}

	for _, c := range base {
		if _, exists := propMap[c.WhenChanged]; !exists {
			diff.Removed = append(diff.Removed, c)
		}
	}

	sort.Slice(diff.Added, func(i, j int) bool { return diff.Added[i].WhenChanged < diff.Added[j].WhenChanged })
	sort.Slice(diff.Removed, func(i, j int) bool { return diff.Removed[i].WhenChanged < diff.Removed[j].WhenChanged })
	sort.Slice(diff.Modified, func(i, j int) bool { return diff.Modified[i].WhenChanged < diff.Modified[j].WhenChanged })

	return diff
}

func diffRuleTunings(base, proposed map[string]PolicyRuleTuning) RuleTuningDiff {
	diff := RuleTuningDiff{
		Added:    make(map[string]PolicyRuleTuning),
		Removed:  make(map[string]PolicyRuleTuning),
		Modified: make(map[string]RuleModifiedDiff),
	}

	for rName, propTuning := range proposed {
		baseTuning, exists := base[rName]
		if !exists {
			diff.Added[rName] = propTuning
		} else {
			// Compare enabled
			enabledDiff := false
			if (propTuning.Enabled == nil) != (baseTuning.Enabled == nil) {
				enabledDiff = true
			} else if propTuning.Enabled != nil && *propTuning.Enabled != *baseTuning.Enabled {
				enabledDiff = true
			}

			severityDiff := propTuning.Severity != baseTuning.Severity

			if enabledDiff || severityDiff {
				diff.Modified[rName] = RuleModifiedDiff{
					Rule:     rName,
					Base:     baseTuning,
					Proposed: propTuning,
				}
			}
		}
	}

	for rName, baseTuning := range base {
		if _, exists := proposed[rName]; !exists {
			diff.Removed[rName] = baseTuning
		}
	}

	return diff
}

func diffPathOverrides(base, proposed map[string]map[string]PolicyRuleTuning) PathOverrideDiff {
	diff := PathOverrideDiff{
		Added:    make(map[string]map[string]PolicyRuleTuning),
		Removed:  make(map[string]map[string]PolicyRuleTuning),
		Modified: make(map[string]RuleTuningDiff),
	}

	for pathGlob, propRules := range proposed {
		baseRules, exists := base[pathGlob]
		if !exists {
			diff.Added[pathGlob] = propRules
		} else {
			ruleDiff := diffRuleTunings(baseRules, propRules)
			if len(ruleDiff.Added) > 0 || len(ruleDiff.Removed) > 0 || len(ruleDiff.Modified) > 0 {
				diff.Modified[pathGlob] = ruleDiff
			}
		}
	}

	for pathGlob, baseRules := range base {
		if _, exists := proposed[pathGlob]; !exists {
			diff.Removed[pathGlob] = baseRules
		}
	}

	return diff
}

// DiffPolicies computes the differences between base and proposed policy.
func DiffPolicies(base, proposed ReviewPolicy) PolicyDiffResult {
	res := PolicyDiffResult{
		Valid:           true,
		RiskPaths:       diffStringSlices(base.RiskPaths, proposed.RiskPaths),
		ForbiddenPaths:  diffStringSlices(base.ForbiddenPaths, proposed.ForbiddenPaths),
		RequireTogether: diffCouplings(base.RequireTogether, proposed.RequireTogether),
		Rules:           diffRuleTunings(base.Rules, proposed.Rules),
		Paths:           diffPathOverrides(base.Paths, proposed.Paths),
	}

	hasChanges := len(res.RiskPaths.Added) > 0 || len(res.RiskPaths.Removed) > 0 ||
		len(res.ForbiddenPaths.Added) > 0 || len(res.ForbiddenPaths.Removed) > 0 ||
		len(res.RequireTogether.Added) > 0 || len(res.RequireTogether.Removed) > 0 || len(res.RequireTogether.Modified) > 0 ||
		len(res.Rules.Added) > 0 || len(res.Rules.Removed) > 0 || len(res.Rules.Modified) > 0 ||
		len(res.Paths.Added) > 0 || len(res.Paths.Removed) > 0 || len(res.Paths.Modified) > 0

	res.HasChanges = hasChanges
	return res
}

func formatTuning(t PolicyRuleTuning) string {
	var parts []string
	if t.Enabled != nil {
		parts = append(parts, fmt.Sprintf("enabled=%v", *t.Enabled))
	}
	if t.Severity != "" {
		parts = append(parts, fmt.Sprintf("severity=%s", t.Severity))
	}
	if len(parts) == 0 {
		return "{}"
	}
	return strings.Join(parts, ", ")
}

// FormatPolicyDiff renders a human-readable text presentation of policy changes.
func FormatPolicyDiff(res PolicyDiffResult) string {
	var sb strings.Builder

	if !res.Valid {
		sb.WriteString("Policy Validation FAILED:\n")
		for _, errStr := range res.ValidationErrors {
			sb.WriteString("  ! " + errStr + "\n")
		}
		return sb.String()
	}

	if !res.HasChanges {
		return "No configuration differences detected between base and proposed policy.\n"
	}

	sb.WriteString("Policy Configuration Diff:\n")

	// Risk paths
	if len(res.RiskPaths.Added) > 0 || len(res.RiskPaths.Removed) > 0 {
		sb.WriteString("\n  Risk Paths:\n")
		for _, p := range res.RiskPaths.Added {
			sb.WriteString("    + " + p + "\n")
		}
		for _, p := range res.RiskPaths.Removed {
			sb.WriteString("    - " + p + "\n")
		}
	}

	// Forbidden paths
	if len(res.ForbiddenPaths.Added) > 0 || len(res.ForbiddenPaths.Removed) > 0 {
		sb.WriteString("\n  Forbidden Paths:\n")
		for _, p := range res.ForbiddenPaths.Added {
			sb.WriteString("    + " + p + "\n")
		}
		for _, p := range res.ForbiddenPaths.Removed {
			sb.WriteString("    - " + p + "\n")
		}
	}

	// Require together
	if len(res.RequireTogether.Added) > 0 || len(res.RequireTogether.Removed) > 0 || len(res.RequireTogether.Modified) > 0 {
		sb.WriteString("\n  Require Together:\n")
		for _, c := range res.RequireTogether.Added {
			sb.WriteString(fmt.Sprintf("    + when %q changes -> also change %v\n", c.WhenChanged, c.AlsoChange))
		}
		for _, c := range res.RequireTogether.Removed {
			sb.WriteString(fmt.Sprintf("    - when %q changes -> also change %v\n", c.WhenChanged, c.AlsoChange))
		}
		for _, m := range res.RequireTogether.Modified {
			sb.WriteString(fmt.Sprintf("    ~ when %q changes:\n", m.WhenChanged))
			sb.WriteString(fmt.Sprintf("        from: %v\n", m.BaseAlsoChange))
			sb.WriteString(fmt.Sprintf("        to:   %v\n", m.PropAlsoChange))
		}
	}

	// Rules
	if len(res.Rules.Added) > 0 || len(res.Rules.Removed) > 0 || len(res.Rules.Modified) > 0 {
		sb.WriteString("\n  Rule Overrides:\n")
		for r, t := range res.Rules.Added {
			sb.WriteString(fmt.Sprintf("    + %s: %s\n", r, formatTuning(t)))
		}
		for r, t := range res.Rules.Removed {
			sb.WriteString(fmt.Sprintf("    - %s: %s\n", r, formatTuning(t)))
		}
		for r, m := range res.Rules.Modified {
			sb.WriteString(fmt.Sprintf("    ~ %s: %s -> %s\n", r, formatTuning(m.Base), formatTuning(m.Proposed)))
		}
	}

	// Paths
	if len(res.Paths.Added) > 0 || len(res.Paths.Removed) > 0 || len(res.Paths.Modified) > 0 {
		sb.WriteString("\n  Path Overrides:\n")
		for p, rMap := range res.Paths.Added {
			sb.WriteString(fmt.Sprintf("    + %q:\n", p))
			for r, t := range rMap {
				sb.WriteString(fmt.Sprintf("        + %s: %s\n", r, formatTuning(t)))
			}
		}
		for p, rMap := range res.Paths.Removed {
			sb.WriteString(fmt.Sprintf("    - %q:\n", p))
			for r, t := range rMap {
				sb.WriteString(fmt.Sprintf("        - %s: %s\n", r, formatTuning(t)))
			}
		}
		for p, diff := range res.Paths.Modified {
			sb.WriteString(fmt.Sprintf("    ~ %q:\n", p))
			for r, t := range diff.Added {
				sb.WriteString(fmt.Sprintf("        + %s: %s\n", r, formatTuning(t)))
			}
			for r, t := range diff.Removed {
				sb.WriteString(fmt.Sprintf("        - %s: %s\n", r, formatTuning(t)))
			}
			for r, m := range diff.Modified {
				sb.WriteString(fmt.Sprintf("        ~ %s: %s -> %s\n", r, formatTuning(m.Base), formatTuning(m.Proposed)))
			}
		}
	}

	return sb.String()
}
