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

	shellPrefixKeywords = map[string]bool{
		"if": true, "then": true, "else": true, "elif": true, "while": true, "until": true,
		"do": true, "!": true, "time": true, "exec": true, "command": true, "(": true, "{": true,
	}

	runnerLaunchers = map[string]bool{
		"uv": true, "poetry": true, "pipx": true, "pdm": true, "hatch": true, "rye": true, "pipenv": true,
	}

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

// stripShellCommentAndQuotes removes comments and quote characters while keeping quoted
// word content, so quoted executables and modules stay visible. Command separators inside
// quotes are blanked so quoted text cannot create new command segments.
func stripShellCommentAndQuotes(line string) string {
	b := strings.Builder{}
	b.Grow(len(line))
	var quote byte
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if quote != 0 {
			switch {
			case ch == quote:
				quote = 0
			case ch == '\\' && quote == '"' && i+1 < len(line):
				i++
				b.WriteByte(line[i])
			case ch == ';' || ch == '|' || ch == '&':
				b.WriteByte(' ')
			default:
				b.WriteByte(ch)
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			quote = ch
			continue
		}
		if ch == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			break
		}
		b.WriteByte(ch)
	}
	return b.String()
}

// commandFields strips env assignments, shell control keywords, and runner launchers
// (e.g. `uv run`) so the first field is the executable actually invoked.
func commandFields(seg string) []string {
	fields := strings.Fields(seg)
	for len(fields) > 0 {
		head := strings.ToLower(fields[0])
		switch {
		case isEnvAssignment(fields[0]) || shellPrefixKeywords[head]:
			fields = fields[1:]
		case runnerLaunchers[head] && len(fields) >= 2 && fields[1] == "run":
			fields = fields[2:]
		default:
			return fields
		}
	}
	return fields
}

func commandBase(field string) string {
	cmd := strings.ToLower(field)
	if idx := strings.LastIndexByte(cmd, '/'); idx != -1 {
		cmd = cmd[idx+1:]
	}
	return cmd
}

func isPythonExecutable(cmd string) bool {
	return cmd == "python" || cmd == "python3" || strings.HasPrefix(cmd, "python3.")
}

func isPreflightCommand(seg string) bool {
	fields := commandFields(seg)
	return len(fields) >= 3 && isPythonExecutable(commandBase(fields[0])) &&
		fields[1] == "-c" && strings.HasPrefix(fields[2], "import")
}

func lineHasPreflight(raw string) bool {
	return slices.ContainsFunc(splitShellCommands(stripShellCommentAndQuotes(raw)), isPreflightCommand)
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
	fields := commandFields(seg)
	if len(fields) == 0 {
		return false
	}
	cmd := commandBase(fields[0])
	if runnerNames[cmd] && cmd != "unittest" {
		return true
	}
	if isPythonExecutable(cmd) && len(fields) >= 3 && fields[1] == "-m" {
		return runnerNames[strings.ToLower(fields[2])]
	}
	return false
}

// findShellRunnerLines returns runner lines that execute before any preflight check.
// Runners after a preflight are covered by it; a preflight after a runner does not count.
func findShellRunnerLines(text string, start int) []int {
	var lines []int
	for i, raw := range strings.Split(text, "\n") {
		segs := splitShellCommands(stripShellCommentAndQuotes(raw))
		if slices.ContainsFunc(segs, isPreflightCommand) {
			break
		}
		if slices.ContainsFunc(segs, isPythonRunnerCommand) {
			lines = append(lines, start+i)
		}
	}
	return lines
}

func hasDeletedPreflight(deletedLines []string) bool {
	return slices.ContainsFunc(deletedLines, lineHasPreflight)
}

func checkQualityGateBlock(
	b diffSourceBlock, text string, start int, wt bool, seen map[string]bool,
) (gateFindings []Finding) {
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
