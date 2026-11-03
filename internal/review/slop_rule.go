package review

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
)

type SlopRule struct {
	RepositoryRoot string
	WorkingTree    bool
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
		pattern:     regexp.MustCompile(`[=!]=\s*(?:true|false)\b|\b(?:true|false)\s*[=!]=`),
		message:     "Redundant boolean comparison",
		remediation: "Remove the explicit comparison to true/false. Use the boolean expression directly.",
	},
	{
		pattern:     regexp.MustCompile(`(?:\t| {4}){4,}`),
		message:     "Excessive indentation (indicates deep nesting)",
		remediation: "Refactor to reduce nesting depth. Consider using early returns or breaking logic into smaller functions.",
	},
	{
		pattern:     regexp.MustCompile(`\b(?:if|for|while|else|try|catch|finally|switch)\b[^{}]*\{\s*\}`),
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
		} else if isRegexScannable(fd.Path) {
			// Fallback to regex for brace-style source files, or Go files when
			// RepoRoot is not set. Config, data and docs files are never scanned.
			findings = append(findings, r.checkFileRegex(fd)...)
		}
	}

	return findings
}

// regexScannableExts are brace-style source files where the regex heuristics
// are meaningful. Everything else (JSON, YAML, Markdown, Makefiles, Python...)
// would produce false positives such as "{}" literals or tab indentation.
var regexScannableExts = map[string]bool{
	".go": true, ".js": true, ".jsx": true, ".ts": true, ".tsx": true,
	".java": true, ".kt": true, ".c": true, ".h": true, ".cc": true,
	".cpp": true, ".hpp": true, ".cs": true, ".rs": true, ".swift": true,
	".php": true,
}

func isRegexScannable(file string) bool {
	return regexScannableExts[strings.ToLower(path.Ext(file))]
}

func (r SlopRule) checkFileRegex(fd FileDiff) []Finding {
	var findings []Finding
	// AddedLines is in diff order, so findings stay deterministic.
	for _, line := range fd.AddedLines {
		text := fd.AddedText[line]
		trimmed := strings.TrimSpace(text)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue
		}
		for _, slopPattern := range slopPatterns {
			if !slopPattern.pattern.MatchString(text) {
				continue
			}
			findings = append(findings, Finding{
				Rule:        "code-slop",
				Severity:    "low",
				File:        fd.Path,
				Line:        line,
				Message:     slopPattern.message,
				Remediation: slopPattern.remediation,
			})
		}
	}

	return findings
}

func isBoolLiteral(e ast.Expr) bool {
	ident, ok := e.(*ast.Ident)
	return ok && (ident.Name == "true" || ident.Name == "false")
}

func isControlFlow(n ast.Node) bool {
	switch n.(type) {
	case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
		return true
	default:
		return false
	}
}

type slopInspector struct {
	file       string
	fset       *token.FileSet
	lineMap    map[int]bool
	findings   []Finding
	seen       map[string]bool
	depth      int
	stack      []ast.Node
	counted    []bool // parallel to stack: whether the node incremented depth
	depthStack []int
	comments   []*ast.CommentGroup
}

// hasCommentWithin reports whether a comment sits inside the block's braces.
func (v *slopInspector) hasCommentWithin(b *ast.BlockStmt) bool {
	for _, cg := range v.comments {
		if cg.Pos() > b.Lbrace && cg.End() < b.Rbrace {
			return true
		}
	}
	return false
}

// checkEmptyBlock reports a control-flow body that is empty and has no
// explanatory comment. Function bodies, "select {}" and "for {}" are
// intentionally ignored: they are stubs or deliberate blocking.
func (v *slopInspector) checkEmptyBlock(b *ast.BlockStmt) {
	if b == nil || len(b.List) != 0 || v.hasCommentWithin(b) {
		return
	}
	line := v.fset.Position(b.Lbrace).Line
	if v.lineMap[line] {
		v.addFinding(line, "Empty block", "Remove the empty block or add a comment explaining why it is empty.")
	}
}

// countsAsNesting is true for control flow that adds a nesting level. An
// "else if" is a sibling branch of its parent "if", not a deeper level.
func countsAsNesting(parent, n ast.Node) bool {
	if !isControlFlow(n) {
		return false
	}
	if p, ok := parent.(*ast.IfStmt); ok && p.Else == n {
		return false
	}
	return true
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
	var content []byte
	var err error
	if r.WorkingTree {
		content, err = os.ReadFile(path.Join(r.RepositoryRoot, file))
	} else {
		content, err = git.StagedFileContent(r.RepositoryRoot, file)
	}
	if err != nil {
		source := "staged"
		if r.WorkingTree {
			source = "working-tree"
		}
		return []Finding{{
			Rule:        "code-slop-analysis-error",
			Severity:    "high",
			File:        file,
			Line:        0,
			Message:     "Failed to read " + source + " content: " + err.Error(),
			Remediation: "Ensure the file is readable and the repository is accessible.",
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
			Message:     "Failed to parse " + map[bool]string{true: "working-tree", false: "staged"}[r.WorkingTree] + " Go code: " + err.Error(),
			Remediation: "Fix syntax errors in the analyzed Go file.",
		}}
	}

	if ast.IsGenerated(f) {
		return nil
	}

	lineMap := make(map[int]bool, len(addedLines))
	for _, l := range addedLines {
		lineMap[l] = true
	}

	inspector := &slopInspector{
		comments: f.Comments,
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
				last := len(inspector.stack) - 1
				top := inspector.stack[last]
				if inspector.counted[last] {
					inspector.depth--
				}
				inspector.stack = inspector.stack[:last]
				inspector.counted = inspector.counted[:last]
				switch top.(type) {
				case *ast.FuncDecl, *ast.FuncLit:
					inspector.depth = inspector.depthStack[len(inspector.depthStack)-1]
					inspector.depthStack = inspector.depthStack[:len(inspector.depthStack)-1]
				}
			}
			return false
		}

		var parent ast.Node
		if len(inspector.stack) > 0 {
			parent = inspector.stack[len(inspector.stack)-1]
		}

		switch n.(type) {
		case *ast.FuncDecl, *ast.FuncLit:
			inspector.depthStack = append(inspector.depthStack, inspector.depth)
			inspector.depth = 0
		}

		counted := countsAsNesting(parent, n)
		inspector.stack = append(inspector.stack, n)
		inspector.counted = append(inspector.counted, counted)
		line := inspector.fset.Position(n.Pos()).Line

		if counted {
			inspector.depth++
			if inspector.depth >= 4 && inspector.lineMap[line] {
				inspector.addFinding(line, "Excessive AST nesting depth (4+ levels)", "Refactor to reduce nesting depth. Consider using early returns or breaking logic into smaller functions.")
			}
		}

		switch node := n.(type) {
		case *ast.BinaryExpr:
			if inspector.lineMap[line] && (node.Op == token.EQL || node.Op == token.NEQ) {
				if isBoolLiteral(node.X) || isBoolLiteral(node.Y) {
					inspector.addFinding(line, "Redundant boolean comparison", "Remove the explicit comparison to true/false. Use the boolean expression directly.")
				}
			}
		case *ast.IfStmt:
			inspector.checkEmptyBlock(node.Body)
			if els, ok := node.Else.(*ast.BlockStmt); ok {
				inspector.checkEmptyBlock(els)
			}
		case *ast.ForStmt:
			// "for {}" is a deliberate infinite loop, not slop.
			if node.Init != nil || node.Cond != nil || node.Post != nil {
				inspector.checkEmptyBlock(node.Body)
			}
		case *ast.RangeStmt:
			inspector.checkEmptyBlock(node.Body)
		}

		return true
	})

	return inspector.findings
}
