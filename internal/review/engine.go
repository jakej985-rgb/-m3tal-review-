package review

import "sync"

type Engine struct {
	rules []Rule
}

func NewEngine(rules ...Rule) *Engine {
	return &Engine{
		rules: rules,
	}
}

func (e *Engine) Run(diff string) []Finding {
	// Rules are independent; run them concurrently but concatenate results
	// in registration order so output stays deterministic.
	results := make([][]Finding, len(e.rules))
	var wg sync.WaitGroup
	for i, rule := range e.rules {
		wg.Add(1)
		go func(i int, rule Rule) {
			defer wg.Done()
			results[i] = checkRuleSafely(rule, diff)
		}(i, rule)
	}
	wg.Wait()

	var findings []Finding
	for _, ruleFindings := range results {
		for i := range ruleFindings {
			if ruleFindings[i].Category == "" {
				ruleFindings[i].Category = categoryForRule(ruleFindings[i].Rule)
			}
		}
		findings = append(findings, ruleFindings...)
	}

	return findings
}

func categoryForRule(rule string) string {
	switch rule {
	case "hardcoded-credential", "world-writable-file-mode", "insecure-tls-verification", "risky-shell-execution":
		return "security"
	case "review-risk":
		return "risk"
	case "review-policy":
		return "drift"
	case "code-slop-analysis-error", "repository-lint", "review-policy-config-error":
		return "confidence"
	default:
		return "review"
	}
}

// checkRuleSafely runs a rule and converts a panic into a confidence finding
// so one buggy or hostile-input-triggering rule cannot crash the review.
func checkRuleSafely(rule Rule, diff string) (findings []Finding) {
	defer func() {
		if r := recover(); r != nil {
			findings = []Finding{{
				Rule:        rule.Name() + "-error",
				Severity:    "medium",
				Message:     "Rule " + rule.Name() + " failed during analysis",
				Remediation: "Report this as a bug; the rule may have hit an unhandled edge case.",
			}}
		}
	}()
	return rule.Check(diff)
}
