package review

type Engine struct {
	rules []Rule
}

func NewEngine(rules ...Rule) *Engine {
	return &Engine{
		rules: rules,
	}
}

func (e *Engine) Run(diff string) []Finding {
	var findings []Finding

	for _, rule := range e.rules {
		ruleFindings := rule.Check(diff)
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
