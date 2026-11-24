package cli

import (
	"fmt"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// defaultRules delegates to the review-owned registry so the CLI no longer
// enumerates every rule type.
func defaultRules(repositoryRoot string) []review.Rule {
	return review.DefaultRules(repositoryRoot)
}

func defaultRulesWithOptions(repositoryRoot string, degraded bool) []review.Rule {
	return review.DefaultRulesWithOptions(repositoryRoot, degraded)
}

// loadCLIRules assembles the default, framework, and custom rule sets shared by
// the review and audit commands.
func loadCLIRules(repositoryRoot string, degraded bool, diff string, framework []string, rulesFile string) ([]review.Rule, []review.CheckResult, error) {
	rules := defaultRulesWithOptions(repositoryRoot, degraded)

	_, frameworkRules, frameworkChecks := review.ResolveFrameworkPacks(repositoryRoot, diff, framework)
	rules = append(rules, frameworkRules...)

	customRulesFile := review.FindCustomRulesFile(repositoryRoot, rulesFile)
	if customRulesFile != "" {
		cRules, err := review.LoadCustomRulesFile(customRulesFile, repositoryRoot)
		if err != nil {
			return nil, nil, fmt.Errorf("custom rules error: %w", err)
		}
		rules = append(rules, cRules...)
	}

	return rules, frameworkChecks, nil
}
