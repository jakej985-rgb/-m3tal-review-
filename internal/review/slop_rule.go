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

	// Parse diff to find added lines
	addedLines := make(map[string][]int)

	var currentFile string
	lineNumber := 0

	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			continue
		}

		if matches := hunkHeader.FindStringSubmatch(line); matches != nil {
			lineNumber, _ = strconv.Atoi(matches[1])
			continue
		}

		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			addedLines[currentFile] = append(addedLines[currentFile], lineNumber)
			lineNumber++
			continue
		}

		if strings.HasPrefix(line, " ") {
			lineNumber++
		}
	}

	for file, lines := range addedLines {
		if file == "/dev/null" {
			continue
		}
		if strings.HasSuffix(file, ".go") && r.RepositoryRoot != "" {
			findings = append(findings, r.checkGoFileAST(file, lines)...)
		} else {
			// Fallback to regex for non-Go files or if RepoRoot is not set
			findings = append(findings, r.checkFileRegex(diff, file, lines)...)
		}
	}

	return findings
}

func (r SlopRule) checkFileRegex(diff string, targetFile string, addedLines []int) []Finding {
	var findings []Finding

	var currentFile string
	lineNumber := 0

	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			continue
		}

		if matches := hunkHeader.FindStringSubmatch(line); matches != nil {
			lineNumber, _ = strconv.Atoi(matches[1])
			continue
		}

		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			if currentFile == targetFile {
				addedLine := strings.TrimPrefix(line, "+")

				if strings.HasPrefix(strings.TrimSpace(addedLine), "//") || strings.HasPrefix(strings.TrimSpace(addedLine), "/*") {
					lineNumber++
					continue
				}

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
			lineNumber++
			continue
		}

		if strings.HasPrefix(line, " ") {
			lineNumber++
		}
	}

	return findings
}

func isBoolLiteral(e ast.Expr) bool {
	ident, ok := e.(*ast.Ident)
	return ok && (ident.Name == "true" || ident.Name == "false")
}

type slopVisitor struct {
	file     string
	fset     *token.FileSet
	lineMap  map[int]bool
	findings []Finding
	depth    int
	seen     map[string]bool
}

func (v *slopVisitor) addFinding(line int, message, remediation string) {
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

func (v *slopVisitor) Visit(n ast.Node) ast.Visitor {
	if n == nil {
		return nil
	}

	pos := v.fset.Position(n.Pos())
	line := pos.Line

	isBlock := false
	if _, ok := n.(*ast.BlockStmt); ok {
		isBlock = true
		v.depth++
		if v.depth >= 4 && v.lineMap[line] {
			v.addFinding(line, "Excessive AST nesting depth (4+ levels)", "Refactor to reduce nesting depth. Consider using early returns or breaking logic into smaller functions.")
		}
	}

	if v.lineMap[line] {
		if binExpr, ok := n.(*ast.BinaryExpr); ok {
			if binExpr.Op == token.EQL || binExpr.Op == token.NEQ {
				if isBoolLiteral(binExpr.X) || isBoolLiteral(binExpr.Y) {
					v.addFinding(line, "Redundant boolean comparison", "Remove the explicit comparison to true/false. Use the boolean expression directly.")
				}
			}
		}

		if block, ok := n.(*ast.BlockStmt); ok {
			if len(block.List) == 0 {
				v.addFinding(line, "Empty block", "Remove the empty block or add a comment explaining why it is empty.")
			}
		}
	}

	if isBlock {
		return &slopWrapperVisitor{v}
	}
	return v
}

type slopWrapperVisitor struct {
	v *slopVisitor
}

func (w *slopWrapperVisitor) Visit(n ast.Node) ast.Visitor {
	if n == nil {
		w.v.depth--
		return nil
	}
	return w.v.Visit(n)
}

func (r SlopRule) checkGoFileAST(file string, addedLines []int) []Finding {
	content, err := git.StagedFileContent(r.RepositoryRoot, file)
	if err != nil {
		// If git show fails because the file is deleted (e.g. fatal: path '...' exists on disk, but not in ...),
		// we should NOT fail the analysis. We should just return nil.
		// "Deleted files are handled as deletions, not analysis errors."
		// How do we distinguish? `git show` on a deleted file returns a specific error or we can check diff!
		// Wait, if a file is deleted, the diff has `+++ /dev/null`.
		return []Finding{{
			Rule:        "code-slop-analysis-error",
			Severity:    "high",
			File:        file,
			Line:        0,
			Message:     "Failed to read staged content: " + err.Error(),
			Remediation: "Ensure the file exists in the git index or exclude it.",
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
			Remediation: "Fix syntax errors.",
		}}
	}

	lineMap := make(map[int]bool)
	for _, l := range addedLines {
		lineMap[l] = true
	}

	v := &slopVisitor{
		file:     file,
		fset:     fset,
		lineMap:  lineMap,
		findings: []Finding{},
		seen:     make(map[string]bool),
		depth:    0,
	}

	ast.Walk(v, f)
	return v.findings
}
