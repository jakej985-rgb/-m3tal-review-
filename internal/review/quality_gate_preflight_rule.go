package review

import (
	"context"
	"regexp"
	"slices"
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

	// preflightCheckRe matches early preflight python dependency checks
	preflightCheckRe = regexp.MustCompile(`(?i)python3?\s+-c\s+["']import\s+[^"']*["']`)

	runnerNames = map[string]bool{
		"unittest": true,
		"pytest":   true,
		"flake8":   true,
		"pylint":   true,
		"mypy":     true,
		"ruff":     true,
	}
)

func (r QualityGatePreflightRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func stripShellCommentAndQuotes(line string) string {
	b := strings.Builder{}
	b.Grow(len(line))
	inString, stringChar := false, byte(0)
	for i := 0; i < len(line); i++ {
		if nextI, ok := scanStringLiteral(line, i, &inString, &stringChar); ok {
			b.WriteByte(' ')
			i = nextI
			continue
		}
		if line[i] == '#' {
			break
		}
		b.WriteByte(line[i])
	}
	res := b.String()
	return res
}

func splitShellCommands(line string) []string {
	replacer := strings.NewReplacer("&&", "\n", "||", "\n", ";", "\n", "|", "\n", "$(", "\n")
	return strings.Split(replacer.Replace(line), "\n")
}

func isEnvAssignment(tok string) bool {
	eq := strings.IndexByte(tok, '=')
	return eq > 0 && !strings.HasPrefix(tok, "-")
}

func isPythonRunnerCommand(seg string) bool {
	fields := strings.Fields(seg)
	for len(fields) > 0 && isEnvAssignment(fields[0]) {
		fields = fields[1:]
	}
	if len(fields) == 0 {
		return false
	}
	cmd := strings.ToLower(fields[0])
	if idx := strings.LastIndexByte(cmd, '/'); idx != -1 {
		cmd = cmd[idx+1:]
	}
	if runnerNames[cmd] && cmd != "unittest" {
		return true
	}
	if (cmd == "python" || cmd == "python3") && len(fields) >= 3 && fields[1] == "-m" {
		return runnerNames[strings.ToLower(fields[2])]
	}
	return false
}

func findShellRunnerLines(text string, start int) []int {
	var lines []int
	for i, raw := range strings.Split(text, "\n") {
		segs := splitShellCommands(stripShellCommentAndQuotes(raw))
		if slices.ContainsFunc(segs, isPythonRunnerCommand) {
			lines = append(lines, start+i)
		}
	}
	return lines
}

func hasDeletedPreflight(deletedLines []string) bool {
	return slices.ContainsFunc(deletedLines, preflightCheckRe.MatchString)
}

func checkQualityGateBlock(
	b diffSourceBlock, text string, start int, wt bool, seen map[string]bool,
) (gateFindings []Finding) {
	if preflightCheckRe.MatchString(text) {
		return gateFindings
	}
	runnerLines := findShellRunnerLines(text, start)
	if len(runnerLines) == 0 {
		return gateFindings
	}
	deletedPreflight := hasDeletedPreflight(b.deletedLines)
	for _, lineNum := range runnerLines {
		if !shouldReportAddedFinding(b, lineNum, wt || deletedPreflight, seen) {
			continue
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
	return gateFindings
}

func (r QualityGatePreflightRule) CheckContext(ctx context.Context, diff string) []Finding {
	return executeBlockRule(ctx, diff, r.repositoryRoot, r.workingTree, func(f string) bool {
		return gateScriptFileRe.MatchString(f)
	}, func(b diffSourceBlock, text string, start int, seen map[string]bool) []Finding {
		return checkQualityGateBlock(b, text, start, r.workingTree, seen)
	})
}
