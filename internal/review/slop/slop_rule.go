package slop

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

type SlopRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (SlopRule) Name() string {
	return "code-slop"
}

func (r SlopRule) Analyze(fileDiffs []FileDiff) []Finding {
	var findings []Finding
	for _, fd := range fileDiffs {
		// Do not attempt AST analysis on deleted files
		if fd.ChangeType == FileDeleted {
			continue
		}

		if len(fd.AddedLines) == 0 {
			continue
		}

		findings = append(findings, r.checkFile(fd)...)
		findings = append(findings, checkSlopLineExtras(fd)...)
	}
	findings = append(findings, crossFileDuplicateFindings(fileDiffs)...)

	return findings
}

func (r SlopRule) checkFile(fd FileDiff) []Finding {
	if r.RepositoryRoot == "" {
		if fd.Source != "" {
			if (language.CodeChecker{}).Language(fd.Path) == language.LanguageGo {
				if _, err := parser.ParseFile(token.NewFileSet(), fd.Path, fd.Source, parser.AllErrors); err != nil {
					return r.checkAddedLineRegex(fd)
				}
			}
			return analyzeSource(fd, fd.Source)
		}
		if source, err := r.readImplicitSource(fd.Path); err == nil && sourceMatchesDiff(fd, source) {
			return analyzeSource(fd, string(source))
		}
	}
	switch (language.CodeChecker{}).Language(fd.Path) {
	case language.LanguageGo:
		if r.RepositoryRoot != "" {
			return r.checkGoFileAST(fd.Path, fd.AddedLines)
		}
		return r.checkAddedLineRegex(fd)
	case language.LanguageJavaScript:
		if r.RepositoryRoot != "" {
			return r.checkJavaScriptSyntax(fd.Path, fd.AddedLines)
		}
		return r.checkJavaScriptRegex(fd)
	case language.LanguageTypeScript:
		if r.RepositoryRoot != "" {
			return r.checkTypeScriptSyntax(fd.Path, fd.AddedLines)
		}
		return r.checkTypeScriptRegex(fd)
	case language.LanguagePython:
		if r.RepositoryRoot != "" {
			return r.checkPythonSyntax(fd.Path, fd.AddedLines)
		}
		return r.checkPythonAddedLineRegex(fd)
	case language.LanguageJava:
		if r.RepositoryRoot != "" {
			return r.checkJavaSyntax(fd.Path, fd.AddedLines)
		}
		return r.checkAddedLineRegex(fd)
	case language.LanguageKotlin:
		if r.RepositoryRoot != "" {
			return r.checkKotlinSyntax(fd.Path, fd.AddedLines)
		}
		return r.checkAddedLineRegex(fd)
	case language.LanguageC:
		if r.RepositoryRoot != "" {
			return r.checkCSyntax(fd.Path, fd.AddedLines)
		}
		return r.checkAddedLineRegex(fd)
	case language.LanguageCpp:
		if r.RepositoryRoot != "" {
			return r.checkCppSyntax(fd.Path, fd.AddedLines)
		}
		return r.checkAddedLineRegex(fd)
	case language.LanguageCSharp:
		if r.RepositoryRoot != "" {
			return r.checkCSharpSyntax(fd.Path, fd.AddedLines)
		}
		return r.checkAddedLineRegex(fd)
	case language.LanguageRust:
		if r.RepositoryRoot != "" {
			return r.checkRustSyntax(fd.Path, fd.AddedLines)
		}
		return r.checkAddedLineRegex(fd)
	case language.LanguageSwift:
		if r.RepositoryRoot != "" {
			return r.checkSwiftSyntax(fd.Path, fd.AddedLines)
		}
		return r.checkAddedLineRegex(fd)
	case language.LanguagePHP:
		if r.RepositoryRoot != "" {
			return r.checkPHPSyntax(fd.Path, fd.AddedLines)
		}
		return r.checkAddedLineRegex(fd)
	default:
		return nil
	}
}

func sourceMatchesDiff(fd FileDiff, source []byte) bool {
	// Without context, matching only added lines cannot establish that this file
	// is the same source snapshot represented by the diff (for example, -U0).
	if len(fd.ContextText) == 0 {
		return false
	}
	lines := strings.Split(string(source), "\n")
	for line, text := range fd.ContextText {
		if line < 1 || line > len(lines) || strings.TrimSuffix(lines[line-1], "\r") != strings.TrimSuffix(text, "\r") {
			return false
		}
	}
	for _, line := range fd.AddedLines {
		if line < 1 || line > len(lines) {
			return false
		}
		if strings.TrimSuffix(lines[line-1], "\r") != strings.TrimSuffix(fd.AddedText[line], "\r") {
			return false
		}
	}
	return true
}

func (r SlopRule) readImplicitSource(file string) ([]byte, error) {
	if !filepath.IsLocal(file) || file == "." {
		return nil, os.ErrInvalid
	}
	if r.WorkingTree {
		return os.ReadFile(filepath.Join(".", file))
	}
	return git.StagedFileContent(".", file)
}

func analyzeSource(fd FileDiff, source string) []Finding {
	added := addedLineMap(fd.AddedLines)
	switch (language.CodeChecker{}).Language(fd.Path) {
	case language.LanguageGo:
		return analyzeGoSourceAST(fd.Path, []byte(source), fd.AddedLines)
	case language.LanguageJavaScript:
		return analyzeBraceSlop(fd.Path, "JavaScript", source, added)
	case language.LanguageTypeScript:
		return analyzeBraceSlop(fd.Path, "TypeScript", source, added)
	case language.LanguagePython:
		return analyzePythonSlop(fd.Path, source, added)
	case language.LanguageC:
		return analyzeBraceLanguage(fd.Path, source, added, braceLanguageConfig{name: "C", controls: wordSet("if", "for", "while", "switch"), directBlocks: wordSet("else", "do"), depthBlocks: wordSet("do"), allowUnbracedBodies: true, boolLiterals: wordSet("true", "false"), preprocessor: true})
	case language.LanguageCpp:
		return analyzeBraceLanguage(fd.Path, source, added, braceLanguageConfig{name: "C++", controls: wordSet("if", "for", "while", "switch", "catch"), directBlocks: wordSet("else", "try", "do"), depthBlocks: wordSet("try", "do"), allowUnbracedBodies: true, cppIfModifiers: true, boolLiterals: wordSet("true", "false"), cppRawStrings: true, preprocessor: true})
	case language.LanguageJava:
		return analyzeBraceLanguage(fd.Path, source, added, braceLanguageConfig{name: "Java", controls: wordSet("if", "for", "while", "switch", "catch"), directBlocks: wordSet("else", "try", "finally", "do"), depthBlocks: wordSet("try", "do"), allowUnbracedBodies: true, javaTryResources: true, boolLiterals: wordSet("true", "false"), tripleStrings: true})
	case language.LanguageKotlin:
		return analyzeBraceLanguage(fd.Path, source, added, braceLanguageConfig{name: "Kotlin", controls: wordSet("if", "for", "while", "when", "catch"), directBlocks: wordSet("else", "try", "finally", "do"), depthBlocks: wordSet("try", "do"), allowUnbracedBodies: true, nestedBlockComments: true, optionalParen: true, boolLiterals: wordSet("true", "false"), tripleStrings: true, kotlinInterpolation: true})
	case language.LanguageCSharp:
		return analyzeBraceLanguage(fd.Path, source, added, braceLanguageConfig{name: "C#", controls: wordSet("if", "for", "foreach", "while", "switch", "catch"), directBlocks: wordSet("else", "try", "finally", "do"), depthBlocks: wordSet("try", "do"), allowUnbracedBodies: true, boolLiterals: wordSet("true", "false"), csharpVerbatimStrings: true, csharpRawStrings: true, csharpInterpolation: true, preprocessor: true})
	case language.LanguageRust:
		return analyzeBraceLanguage(fd.Path, source, added, braceLanguageConfig{name: "Rust", controls: wordSet("if", "for", "while", "match", "loop"), directBlocks: wordSet("else"), optionalParen: true, rustLetPatterns: true, boolLiterals: wordSet("true", "false"), rustRawStrings: true, nestedBlockComments: true})
	case language.LanguageSwift:
		return analyzeBraceLanguage(fd.Path, source, added, braceLanguageConfig{name: "Swift", controls: wordSet("if", "for", "while", "switch", "guard"), directBlocks: wordSet("else", "do", "repeat"), optionalParen: true, boolLiterals: wordSet("true", "false"), tripleStrings: true, swiftRawStrings: true, preprocessor: true, nestedBlockComments: true, swiftRegexLiterals: true, depthBlocks: wordSet("repeat"), swiftInterpolation: true})
	case language.LanguagePHP:
		return analyzeBraceLanguage(fd.Path, source, added, braceLanguageConfig{name: "PHP", controls: wordSet("if", "for", "foreach", "while", "switch", "catch"), directBlocks: wordSet("else", "try", "finally", "do"), boolLiterals: wordSet("true", "false"), phpComments: true, phpAltSyntax: true, phpHeredoc: true, depthBlocks: wordSet("try", "do"), phpInterpolation: true, strictBoolOperators: true})
	default:
		return nil
	}
}

func (r SlopRule) readSourceForAnalysis(file string) ([]byte, error) {
	if !filepath.IsLocal(file) || file == "." {
		return nil, os.ErrInvalid
	}
	if r.WorkingTree {
		return os.ReadFile(filepath.Join(r.RepositoryRoot, file))
	}
	return git.StagedFileContent(r.RepositoryRoot, file)
}

func (r SlopRule) analysisReadError(file string, err error) []Finding {
	source := "staged"
	if r.WorkingTree {
		source = "working-tree"
	}
	return []Finding{{
		Rule:        "code-slop-analysis-error",
		Severity:    "high",
		File:        file,
		Line:        0,
		Message:     fmt.Sprintf("Failed to read %s content: %s", source, err),
		Remediation: "Ensure the file is readable and the repository is accessible.",
	}}
}

func addedLineMap(lines []int) map[int]bool {
	lineMap := make(map[int]bool, len(lines))
	for _, line := range lines {
		lineMap[line] = true
	}
	return lineMap
}

var genericSlopPatterns = []struct {
	pattern     *regexp.Regexp
	message     string
	remediation string
}{
	{regexp.MustCompile(`[=!]=\s*(?:true|false)\b|\b(?:true|false)\s*[=!]=`), "Redundant boolean comparison", "Remove the explicit comparison to true/false. Use the boolean expression directly."},
	{regexp.MustCompile(`(?:\t| {4}){4,}`), "Excessive indentation (indicates deep nesting)", "Refactor to reduce nesting depth. Consider using early returns or breaking logic into smaller functions."},
	{regexp.MustCompile(`\b(?:if|for|while|else|try|catch|finally|switch)\b[^{}]*\{\s*\}`), "Empty block", "Remove the empty block or add a comment explaining why it is empty."},
}

func (r SlopRule) checkAddedLineRegex(fd FileDiff) []Finding {
	var findings []Finding
	for _, line := range fd.AddedLines {
		text := fd.AddedText[line]
		trimmed := strings.TrimSpace(text)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue
		}
		for _, pattern := range genericSlopPatterns {
			if pattern.message == "Redundant boolean comparison" && !looseBooleanHeuristicSafe(fd.Path) {
				continue
			}
			if pattern.pattern.MatchString(text) {
				findings = append(findings, Finding{Rule: "code-slop", Severity: "low", File: fd.Path, Line: line, Message: pattern.message, Remediation: pattern.remediation})
			}
		}
	}
	return findings
}

func looseBooleanHeuristicSafe(file string) bool {
	switch (language.CodeChecker{}).Language(file) {
	case language.LanguageJavaScript, language.LanguageTypeScript, language.LanguagePython, language.LanguageC, language.LanguageCpp, language.LanguagePHP:
		return false // A regex fallback cannot establish operand types or coercion behavior.
	default:
		return true
	}
}

func appendSlopFinding(findings *[]Finding, seen map[string]bool, file string, line int, message, remediation string) {
	key := strconv.Itoa(line) + ":" + message
	if seen[key] {
		return
	}
	seen[key] = true
	*findings = append(*findings, Finding{Rule: "code-slop", Severity: "low", File: file, Line: line, Message: message, Remediation: remediation})
}

func isBoolLiteral(e ast.Expr) bool {
	switch value := e.(type) {
	case *ast.Ident:
		return value.Name == "true" || value.Name == "false"
	case *ast.ParenExpr:
		return isBoolLiteral(value.X)
	default:
		return false
	}
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
	file         string
	fset         *token.FileSet
	lineMap      map[int]bool
	findings     []Finding
	seen         map[string]bool
	depth        int
	stack        []ast.Node
	counted      []bool // parallel to stack: whether the node incremented depth
	depthStack   []int
	deepStack    []bool
	deepReported bool
	comments     []*ast.CommentGroup
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
	if !filepath.IsLocal(file) || file == "." {
		return r.analysisReadError(file, os.ErrInvalid)
	}
	var content []byte
	var err error
	if r.WorkingTree {
		content, err = os.ReadFile(filepath.Join(r.RepositoryRoot, file))
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
	return analyzeGoSourceAST(file, content, addedLines)
}

func analyzeGoSourceAST(file string, content []byte, addedLines []int) []Finding {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, content, parser.ParseComments)
	if err != nil {
		return []Finding{{
			Rule:        "code-slop-analysis-error",
			Severity:    "high",
			File:        file,
			Line:        0,
			Message:     "Failed to parse Go code: " + err.Error(),
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
				if inspector.depth < 4 {
					inspector.deepReported = false
				}
				inspector.stack = inspector.stack[:last]
				inspector.counted = inspector.counted[:last]
				switch top.(type) {
				case *ast.FuncDecl, *ast.FuncLit:
					inspector.depth = inspector.depthStack[len(inspector.depthStack)-1]
					inspector.depthStack = inspector.depthStack[:len(inspector.depthStack)-1]
					inspector.deepReported = inspector.deepStack[len(inspector.deepStack)-1]
					inspector.deepStack = inspector.deepStack[:len(inspector.deepStack)-1]
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
			inspector.deepStack = append(inspector.deepStack, inspector.deepReported)
			inspector.depth = 0
			inspector.deepReported = false
		}

		counted := countsAsNesting(parent, n)
		inspector.stack = append(inspector.stack, n)
		inspector.counted = append(inspector.counted, counted)
		line := inspector.fset.Position(n.Pos()).Line

		if counted {
			inspector.depth++
		}
		if inspector.depth >= 4 && inspector.lineMap[line] && !inspector.deepReported {
			inspector.addFinding(line, "Excessive AST nesting depth (4+ levels)", "Refactor to reduce nesting depth. Consider using early returns or breaking logic into smaller functions.")
			inspector.deepReported = true
		}

		switch node := n.(type) {
		case *ast.BinaryExpr:
			startLine := fset.Position(node.Pos()).Line
			endLine := fset.Position(node.End()).Line
			addedComparison := false
			findingLine := startLine
			for candidate := startLine; candidate <= endLine; candidate++ {
				if inspector.lineMap[candidate] {
					addedComparison = true
					findingLine = candidate
					break
				}
			}
			if addedComparison && (node.Op == token.EQL || node.Op == token.NEQ) {
				if isBoolLiteral(node.X) || isBoolLiteral(node.Y) {
					inspector.addFinding(findingLine, "Redundant boolean comparison", "Remove the explicit comparison to true/false. Use the boolean expression directly.")
				}
			}
			inspector.checkDivBeforeMul(node)
		case *ast.IfStmt:
			inspector.checkEmptyBlock(node.Body)
			if els, ok := node.Else.(*ast.BlockStmt); ok {
				inspector.checkEmptyBlock(els)
			}
			inspector.checkElseAfterTerminator(node)
		case *ast.BlockStmt:
			inspector.checkDeadCode(node)
			inspector.checkBooleanIfReturn(node)
		case *ast.AssignStmt:
			inspector.checkIgnoredCallResult(node)
		case *ast.FuncDecl:
			inspector.checkFunctionSize(node)
			inspector.checkResourceClose(node)
			inspector.checkInitFunc(node)
			inspector.checkCyclomatic(node)
		case *ast.ForStmt:
			// "for {}" is a deliberate infinite loop, not slop.
			if node.Init != nil || node.Cond != nil || node.Post != nil {
				inspector.checkEmptyBlock(node.Body)
			}
			inspector.checkStringConcatLoop(node)
			inspector.checkDeferInLoop(node)
		case *ast.RangeStmt:
			inspector.checkEmptyBlock(node.Body)
			inspector.checkStringConcatLoop(node)
			inspector.checkDeferInLoop(node)
		case *ast.ExprStmt:
			inspector.checkIgnoredErrorCall(node)
			inspector.checkUncheckedAssert(node)
		case *ast.CallExpr:
			if fn := inspector.enclosingFuncDecl(); fn != nil {
				inspector.checkMustCompile(node)
				inspector.checkFatalOutsideMain(fn, node)
			}
			inspector.checkSleep(node)
		}

		return true
	})

	return inspector.findings
}

func boolLiteralValue(e ast.Expr) (bool, bool) {
	switch value := e.(type) {
	case *ast.Ident:
		if value.Name == "true" {
			return true, true
		}
		if value.Name == "false" {
			return false, true
		}
	case *ast.ParenExpr:
		return boolLiteralValue(value.X)
	}
	return false, false
}

// singleBoolReturn reports whether the block consists of a single return of a
// boolean literal, returning the literal's value.
func singleBoolReturn(b *ast.BlockStmt) (bool, bool) {
	if b == nil || len(b.List) != 1 {
		return false, false
	}
	ret, ok := b.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false, false
	}
	return boolLiteralValue(ret.Results[0])
}

// blockEndsWithTerminator reports whether the block's last statement always
// exits the enclosing flow (return, break, continue, or goto).
func blockEndsWithTerminator(b *ast.BlockStmt) bool {
	if b == nil || len(b.List) == 0 {
		return false
	}
	switch stmt := b.List[len(b.List)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BranchStmt:
		return stmt.Tok != token.FALLTHROUGH
	}
	return false
}

func (v *slopInspector) checkElseAfterTerminator(node *ast.IfStmt) {
	if node.Else == nil || !blockEndsWithTerminator(node.Body) {
		return
	}
	line := v.fset.Position(node.Else.Pos()).Line
	if v.lineMap[line] {
		v.addFinding(line, "Else branch after a terminating statement", "Dedent the else body; it can follow the if directly because the if body always exits.")
	}
}

// checkDeadCode flags the first statement that follows a terminating
// statement within the same block.
func (v *slopInspector) checkDeadCode(b *ast.BlockStmt) {
	terminated := false
	for _, stmt := range b.List {
		if terminated {
			line := v.fset.Position(stmt.Pos()).Line
			if v.lineMap[line] {
				v.addFinding(line, "Unreachable code after terminating statement", "Remove the dead code or restructure the control flow.")
			}
			return
		}
		switch s := stmt.(type) {
		case *ast.ReturnStmt:
			terminated = true
		case *ast.BranchStmt:
			terminated = s.Tok != token.FALLTHROUGH
		case *ast.ExprStmt:
			if call, ok := s.X.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "panic" {
					terminated = true
				}
			}
		}
	}
}

// checkBooleanIfReturn flags if/else (or if followed by return) patterns that
// only return boolean literals and can be a single return expression.
func (v *slopInspector) checkBooleanIfReturn(b *ast.BlockStmt) {
	for i, stmt := range b.List {
		ifs, ok := stmt.(*ast.IfStmt)
		if !ok {
			continue
		}
		thenVal, thenOK := singleBoolReturn(ifs.Body)
		if !thenOK {
			continue
		}
		var elseVal bool
		var elseOK bool
		line := v.fset.Position(ifs.Pos()).Line
		if els, ok := ifs.Else.(*ast.BlockStmt); ok {
			elseVal, elseOK = singleBoolReturn(els)
		} else if ifs.Else == nil && i+1 < len(b.List) {
			if ret, ok := b.List[i+1].(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
				elseVal, elseOK = boolLiteralValue(ret.Results[0])
			}
		}
		if !elseOK || elseVal == thenVal {
			continue
		}
		if v.lineMap[line] {
			v.addFinding(line, "If/else returns boolean literals", "Return the condition (or its negation) directly instead of branching on boolean literals.")
		}
	}
}

// checkIgnoredCallResult flags assignments that discard every result of a
// call expression via blank identifiers, e.g. "_ = f()" or "_, _ = g()".
func (v *slopInspector) checkIgnoredCallResult(node *ast.AssignStmt) {
	if len(node.Lhs) == 0 {
		return
	}
	for _, lhs := range node.Lhs {
		id, ok := lhs.(*ast.Ident)
		if !ok || id.Name != "_" {
			return
		}
	}
	hasCall := false
	for _, rhs := range node.Rhs {
		if containsCallExpr(rhs) {
			hasCall = true
			break
		}
	}
	if !hasCall {
		return
	}
	line := v.fset.Position(node.Pos()).Line
	if v.lineMap[line] {
		v.addFinding(line, "Call result discarded with blank identifier", "Handle the returned error or check whether discarding the result is intentional.")
	}
}

func containsCallExpr(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if _, ok := n.(*ast.CallExpr); ok {
			found = true
			return false
		}
		return !found
	})
	return found
}

// checkFunctionSize flags very long functions and functions with many
// parameters.
func (v *slopInspector) checkFunctionSize(node *ast.FuncDecl) {
	if node.Body == nil {
		return
	}
	line := v.fset.Position(node.Pos()).Line
	if !v.lineMap[line] {
		return
	}
	if span := v.fset.Position(node.Body.End()).Line - line; span > 80 {
		v.addFinding(line, "Function exceeds 80 lines", "Consider splitting the function into smaller, focused helpers.")
	}
	params := 0
	if node.Type.Params != nil {
		for _, field := range node.Type.Params.List {
			if len(field.Names) == 0 {
				params++
			} else {
				params += len(field.Names)
			}
		}
	}
	if params > 6 {
		v.addFinding(line, "Function has many parameters ("+strconv.Itoa(params)+")", "Consider grouping related parameters into a struct or options type.")
	}
}
