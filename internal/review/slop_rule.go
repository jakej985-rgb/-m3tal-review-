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
}

func (v *slopVisitor) Visit(n ast.Node) ast.Visitor {
	if n == nil {
		return nil
	}

	pos := v.fset.Position(n.Pos())
	line := pos.Line

	// 3. Excessive nesting (AST depth)
	isBlock := false
	if _, ok := n.(*ast.BlockStmt); ok {
		isBlock = true
		if v.depth >= 4 && v.lineMap[line] {
			v.findings = append(v.findings, Finding{
				Rule:        "code-slop",
				Severity:    "low",
				File:        v.file,
				Line:        line,
				Message:     "Excessive AST nesting depth (4+ levels)",
				Remediation: "Refactor to reduce nesting depth. Consider using early returns or breaking logic into smaller functions.",
			})
		}
	}

	if v.lineMap[line] {
		// 1. Redundant boolean
		if binExpr, ok := n.(*ast.BinaryExpr); ok {
			if binExpr.Op == token.EQL || binExpr.Op == token.NEQ {
				if isBoolLiteral(binExpr.X) || isBoolLiteral(binExpr.Y) {
					v.findings = append(v.findings, Finding{
						Rule:        "code-slop",
						Severity:    "low",
						File:        v.file,
						Line:        line,
						Message:     "Redundant boolean comparison",
						Remediation: "Remove the explicit comparison to true/false. Use the boolean expression directly.",
					})
				}
			}
		}

		// 2. Empty block
		if block, ok := n.(*ast.BlockStmt); ok {
			if len(block.List) == 0 {
				v.findings = append(v.findings, Finding{
					Rule:        "code-slop",
					Severity:    "low",
					File:        v.file,
					Line:        line,
					Message:     "Empty block",
					Remediation: "Remove the empty block or add a comment explaining why it is empty.",
				})
			}
		}
	}

	if isBlock {
		v.depth++
		// Since ast.Walk will call Visit on children and then we can't easily run code after children are done,
		// returning a wrapper visitor is an elegant way to track depth correctly in a single pass.
		return &slopWrapperVisitor{v}
	}

	return v
}

// slopWrapperVisitor decrements depth after block children are visited
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
		// If git show fails (e.g., file deleted), skip AST checking
		return nil
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, content, parser.ParseComments)
	if err != nil {
		return nil // Gracefully fail if parsing fails
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
		depth:    0,
	}

	ast.Walk(v, f)

	return v.findings
}
