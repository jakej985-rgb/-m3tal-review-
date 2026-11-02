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
		findings = append(findings, rule.Check(diff)...)
	}

	return findings
}