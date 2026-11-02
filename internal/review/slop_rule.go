package review

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
)

type SlopRule struct {
	RepositoryRoot string
}

func (SlopRule) Name() string {
	return "code-slop"
}

var slopPatterns = []struct {
	pattern     *regexp.Regexp
	message     string
	remediation string
}{
	{
		pattern:     regexp.MustCompile(`==\s*true\b|\btrue\s*==|!=\s*false\b|\bfalse\s*!=`),
		message:     "Redundant boolean comparison",
		remediation: "Remove the explicit comparison to true/false. Use the boolean expression directly.",
	},
	{
		pattern:     regexp.MustCompile(`(?:\t| {4}){4,}`),
		message:     "Excessive indentation (indicates deep nesting)",
		remediation: "Refactor to reduce nesting depth. Consider using early returns or breaking logic into smaller functions.",
	},
	{
		pattern:     regexp.MustCompile(`\{\s*\}`),
		message:     "Empty block",
		remediation: "Remove the empty block or add a comment explaining why it is empty.",
	},
}

func (r SlopRule) Check(diff string) []Finding {
	var findings []Finding

	fileDiffs := ParseDiff(diff)

	for _, fd := range fileDiffs {
		// Do not attempt AST analysis on deleted files
		if fd.ChangeType == FileDeleted {
			continue
		}

		if len(fd.AddedLines) == 0 {
			continue
		}

		if strings.HasSuffix(fd.Path, ".go") && r.RepositoryRoot != "" {
			findings = append(findings, r.checkGoFileAST(fd.Path, fd.AddedLines)...)
		} else {
			// Fallback to regex for non-Go files or if RepoRoot is not set
			findings = append(findings, r.checkFileRegex(diff, fd.Path, fd.AddedLines)...)
		}
	}

	return findings
}

func (r SlopRule) checkFileRegex(diff string, targetFile string, addedLines []int) []Finding {
	var findings []Finding

	lineMap := make(map[int]bool, len(addedLines))
	for _, l := range addedLines {
		lineMap[l] = true
	}

	var currentFile string
	lineNumber := 0
	inHunk := false

	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			inHunk = false
			parts := strings.Split(strings.TrimPrefix(line, "diff --git "), " ")
			if len(parts) > 1 && strings.HasPrefix(parts[1], "b/") {
				currentFile = strings.TrimPrefix(parts[1], "b/")
			}
			continue
		}

		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			inHunk = false
			continue
		}

		if matches := hunkHeader.FindStringSubmatch(line); matches != nil {
			inHunk = true
			lineNumber, _ = strconv.Atoi(matches[1])
			continue
		}

		if inHunk {
			if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
				if currentFile == targetFile && lineMap[lineNumber] {
					addedLine := strings.TrimPrefix(line, "+")

					if !strings.HasPrefix(strings.TrimSpace(addedLine), "//") && !strings.HasPrefix(strings.TrimSpace(addedLine), "/*") {
						for _, slopPattern := range slopPatterns {
							if slopPattern.pattern.MatchString(addedLine) {
								if slopPattern.message == "Empty block" && strings.Contains(addedLine, "interface{}") {
									continue
								}

								findings = append(findings, Finding{
									Rule:        "code-slop",
									Severity:    "low",
									File:        currentFile,
									Line:        lineNumber,
									Message:     slopPattern.message,
									Remediation: slopPattern.remediation,
								})
							}
						}
					}
				}
				lineNumber++
				continue
			}

			if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
				continue
			}

			if strings.HasPrefix(line, "\\") {
				continue
			}

			if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				lineNumber++
			}
		}
	}

	return findings
}

func isBoolLiteral(e ast.Expr) bool {
	ident, ok := e.(*ast.Ident)
	return ok && (ident.Name == "true" || ident.Name == "false")
}

type slopInspector struct {
	file     string
	fset     *token.FileSet
	lineMap  map[int]bool
	findings []Finding
	seen     map[string]bool
	depth    int
	stack    []ast.Node
}

func (v *slopInspector) addFinding(line int, message, remediation string) {
	key := strconv.Itoa(line) + ":" + message
	if v.seen[key] {
		return
	}
	v.seen[key] = true
	v.findings = append(v.findings, Finding{
		Rule:        "code-slop",
		Severity:    "low",
		File:        v.file,
		Line:        line,
		Message:     message,
		Remediation: remediation,
	})
}

func (r SlopRule) checkGoFileAST(file string, addedLines []int) []Finding {
	content, err := git.StagedFileContent(r.RepositoryRoot, file)
	if err != nil {
		return []Finding{{
			Rule:        "code-slop-analysis-error",
			Severity:    "high",
			File:        file,
			Line:        0,
			Message:     "Failed to read staged content: " + err.Error(),
			Remediation: "Ensure the file exists in the git index and git repository is accessible.",
		}}
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, content, parser.ParseComments)
	if err != nil {
		return []Finding{{
			Rule:        "code-slop-analysis-error",
			Severity:    "high",
			File:        file,
			Line:        0,
			Message:     "Failed to parse staged Go code: " + err.Error(),
			Remediation: "Fix syntax errors in staged Go file.",
		}}
	}

	lineMap := make(map[int]bool, len(addedLines))
	for _, l := range addedLines {
		lineMap[l] = true
	}

	inspector := &slopInspector{
		file:     file,
		fset:     fset,
		lineMap:  lineMap,
		findings: []Finding{},
		seen:     make(map[string]bool),
		depth:    0,
	}

	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			if len(inspector.stack) > 0 {
				top := inspector.stack[len(inspector.stack)-1]
				inspector.stack = inspector.stack[:len(inspector.stack)-1]
				if _, ok := top.(*ast.BlockStmt); ok {
					inspector.depth--
				}
			}
			return false
		}

		inspector.stack = append(inspector.stack, n)
		pos := inspector.fset.Position(n.Pos())
		line := pos.Line

		if _, ok := n.(*ast.BlockStmt); ok {
			inspector.depth++
			if inspector.depth >= 4 && inspector.lineMap[line] {
				inspector.addFinding(line, "Excessive AST nesting depth (4+ levels)", "Refactor to reduce nesting depth. Consider using early returns or breaking logic into smaller functions.")
			}
		}

		if inspector.lineMap[line] {
			if binExpr, ok := n.(*ast.BinaryExpr); ok {
				if binExpr.Op == token.EQL || binExpr.Op == token.NEQ {
					if isBoolLiteral(binExpr.X) || isBoolLiteral(binExpr.Y) {
						inspector.addFinding(line, "Redundant boolean comparison", "Remove the explicit comparison to true/false. Use the boolean expression directly.")
					}
				}
			}

			if block, ok := n.(*ast.BlockStmt); ok {
				if len(block.List) == 0 {
					inspector.addFinding(line, "Empty block", "Remove the empty block or add a comment explaining why it is empty.")
				}
			}
		}

		return true
	})

	return inspector.findings
}
