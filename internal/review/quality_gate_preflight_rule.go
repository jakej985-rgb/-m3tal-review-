package review

import (
	"context"
	"regexp"
	"strings"
)

// QualityGatePreflightRule detects quality gate and CI runner shell scripts that execute
// test runner suites (e.g. python unittest discover) without an early dependency preflight
// check, leading to failure late in the pipeline with ModuleNotFoundError.
type QualityGatePreflightRule struct {
	ruleRuntime
}

func (QualityGatePreflightRule) Name() string {
	return "quality-gate-preflight-dependency"
}

var (
	gateScriptFileRe = regexp.MustCompile(`(?i)(?:quality_gate|gate|check|preflight).*\.sh$`)

	// qualityGateCommandRe matches python test runners and linters
	qualityGateCommandRe = regexp.MustCompile(
		`(?i)(?:python3?\s+-m\s+(?:unittest(?:\s+discover)?|pytest|flake8|pylint|mypy|ruff)\b|` +
			`\b(?:pytest|flake8|pylint|mypy|ruff)\b)`,
	)

	// preflightCheckRe matches early preflight python dependency checks
	preflightCheckRe = regexp.MustCompile(`(?i)python3?\s+-c\s+["']import\s+[^"']*["']`)
)

func (r QualityGatePreflightRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func checkQualityGateBlock(b diffSourceBlock, text string, start int, wt bool, seen map[string]bool) []Finding {
	if !qualityGateCommandRe.MatchString(text) || preflightCheckRe.MatchString(text) {
		return nil
	}
	loc := qualityGateCommandRe.FindStringIndex(text)
	lineNum := start + strings.Count(text[:loc[0]], "\n")
	if !shouldReportAddedFinding(b, lineNum, wt, seen) {
		return nil
	}
	return []Finding{{
		Rule:        "quality-gate-preflight-dependency",
		Severity:    "medium",
		File:        b.file,
		Line:        lineNum,
		Message:     "Quality gate executes Python test runner without an early dependency preflight check",
		Remediation: "Add an early preflight check (python3 -c \"import ...\") before running expensive test suites.",
	}}
}

func (r QualityGatePreflightRule) CheckContext(ctx context.Context, diff string) []Finding {
	return executeBlockRule(ctx, diff, r.repositoryRoot, r.workingTree, func(f string) bool {
		return gateScriptFileRe.MatchString(f)
	}, func(b diffSourceBlock, text string, start int, seen map[string]bool) []Finding {
		return checkQualityGateBlock(b, text, start, r.workingTree, seen)
	})
}
